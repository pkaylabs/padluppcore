from datetime import timedelta
import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Count, Exists, Max, OuterRef, Q
from django.utils import timezone
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView

from .community_access import (
    active_user, can_create_group, can_manage_group, can_manage_task, can_moderate_group,
    can_read_group, group_membership, is_internal, task_membership, visible_messages,
    group_admin_count,
)
from .community_models import (
    CommunityAudit, CommunityCategory, CommunityCreatorApproval, CommunityGroup,
    CommunityInactivityReview, CommunityInvite, CommunityMembership, CommunityReport, CommunityTask, CommunityTaskInvitation,
)
from .community_serializers import (
    CategorySerializer, CommunityTaskSerializer, DecisionSerializer, GroupSerializer,
    GroupWriteSerializer, LeaveSerializer, LifecycleSerializer, MemberActionSerializer,
    ReportSerializer, TaskPatchSerializer, TaskWriteSerializer, user_data,
)
from .community_services import (
    audit, create_group, create_task, decide_group_request, decide_task_request,
    enrollment_status, generate_task_cycles, invite_task_users, join_group, join_task,
    leave_group, leave_task, manage_group_member, notify, notify_admin_shortage,
    require_reason, request_task_link_join, resolve_inactivity_review, review_inactive_members, revoke_group_invitation,
    set_group_status, set_task_status,
)
from .models import ContentReport, Conversation, ConversationMembership, Goal, GoalCheckin, Message, UserBlock
from .permissions import HasCronSecret


def member_data(member, request):
    scope = {'group': member.group} if isinstance(member, CommunityMembership) else {'task': member.task}
    review = CommunityInactivityReview.objects.filter(user=member.user, resolved=False, **scope).first()
    return {'id': member.id, 'user': user_data(member.user, request), 'role': member.role,
            'state': member.state, 'joined_at': member.joined_at, 'is_active': active_user(member.user),
            'muted_until': getattr(member, 'muted_until', None), 'misconduct': getattr(member, 'misconduct', False),
            'inactivity_review': {'id': review.id, 'last_login_at': review.last_login_at} if review else None}


def group_invitation_data(invitation, request):
    base = getattr(settings, 'PADLUPP_APP_URL', 'https://app.padlupp.com').rstrip('/')
    is_link = invitation.user_id is None
    return {'id': invitation.id, 'user': user_data(invitation.user, request),
            'invited_by': user_data(invitation.invited_by, request), 'role': invitation.role,
            'status': invitation.status, 'created_at': invitation.created_at, 'expires_at': invitation.expires_at,
            'is_link': is_link,
            'url': f'{base}/community?group={invitation.group_id}&invite={invitation.token}' if is_link else None}


class CommunityPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


def filter_group_inventory(qs, params):
    qs = qs.annotate(active_member_count=Count('memberships', filter=Q(memberships__state='active', memberships__user__is_active=True, memberships__user__deleted=False), distinct=True),
                     open_report_count=Count('reports', filter=Q(reports__status__in=['pending', 'reviewed']), distinct=True),
                     last_activity_at=Max('conversation__messages__created_at'))
    search = params.get('search', '').strip()
    if search:
        qs = qs.filter(Q(name__icontains=search) | Q(description__icontains=search) | Q(category__name__icontains=search))
    for field in ('category', 'status', 'visibility'):
        value = params.get(field)
        if value:
            if field == 'category':
                value = serializers.IntegerField(min_value=1).run_validation(value)
            qs = qs.filter(**{field: value})
    for param, field in [('min_members', 'active_member_count__gte'), ('max_members', 'active_member_count__lte'),
                         ('min_reports', 'open_report_count__gte'), ('max_reports', 'open_report_count__lte')]:
        if params.get(param) is not None:
            qs = qs.filter(**{field: serializers.IntegerField(min_value=0).run_validation(params[param])})
    for param, field in [('created_after', 'created_at__date__gte'), ('created_before', 'created_at__date__lte')]:
        if params.get(param):
            qs = qs.filter(**{field: serializers.DateField().run_validation(params[param])})
    for param, field in [('active_after', 'last_activity_at__gte'), ('active_before', 'last_activity_at__lte')]:
        if params.get(param):
            qs = qs.filter(**{field: serializers.DateTimeField().run_validation(params[param])})
    order = params.get('ordering', 'category__position,category__name,name')
    mapping = {'activity': 'last_activity_at', 'member_count': 'active_member_count', 'report_count': 'open_report_count',
               'created_at': 'created_at', 'name': 'name', 'category__position': 'category__position', 'category__name': 'category__name'}
    fields = []
    for part in order.split(','):
        direction, key = ('-', part[1:]) if part.startswith('-') else ('', part)
        if key not in mapping:
            raise ValidationError({'ordering': 'Unsupported inventory ordering.'})
        fields.append(direction + mapping[key])
    return qs.order_by(*fields, 'id')


def audit_data(entry, request):
    return {'id': entry.id, 'actor': user_data(entry.actor, request), 'action': entry.action,
            'target_type': entry.target_type, 'target_id': entry.target_id, 'group': entry.group_id,
            'task': entry.task_id, 'reason': entry.reason, 'outcome': entry.outcome, 'created_at': entry.created_at}


def report_data(report, request, group=None):
    actions = []
    if report.message_id and not report.message.recalled_at:
        actions.append('remove_message')
    if report.task_id and (group is None or (report.task.group_id == group.id and can_manage_group(group, request.user))):
        actions.extend(['freeze_task', 'archive_task', 'delete_task'])
    if group is None and is_internal(request.user):
        if report.group_id:
            actions.extend(['freeze_group', 'archive_group', 'delete_group'])
        if report.reported_user_id:
            actions.extend(['warn_user', 'ban_user', 'deactivate_user'])
    evidence_path = (f'/api-v1/community/groups/{group.id}/reports/{report.id}/evidence/' if group else
                     f'/api-v1/community/messages/{report.message_id}/report-evidence/')
    return {'id': report.id, 'reporter': user_data(report.reporter, request), 'reported_user': user_data(report.reported_user, request),
            'group': report.group_id, 'task': report.task_id, 'message': report.message_id,
            'reason': report.reason, 'details': report.details, 'status': report.status,
            'reviewer': user_data(report.reviewer, request), 'reviewed_at': report.reviewed_at,
            'notes': report.notes, 'created_at': report.created_at, 'content_report_id': report.content_report_id,
            'allowed_actions': actions,
            'evidence_url': request.build_absolute_uri(evidence_path) if report.message_id and report.status in ('pending', 'reviewed') else None}


def import_content_reports(group=None):
    qs = ContentReport.objects.filter(community_report__isnull=True).select_related('message__conversation', 'conversation')
    if group:
        qs = qs.filter(Q(message__conversation=group.conversation) | Q(message__isnull=True, conversation=group.conversation))
    for original in qs.iterator(chunk_size=200):
        conversation = original.message.conversation if original.message_id else original.conversation
        source_group = getattr(conversation, 'community_group', None) if conversation else None
        CommunityReport.objects.get_or_create(content_report=original, defaults={
            'reporter': original.reporter, 'reported_user': original.reported_user, 'message': original.message,
            'group': source_group, 'reason': original.reason, 'details': original.details,
            'status': original.status, 'notes': original.moderator_notes})


def filter_reports(qs, params):
    if params.get('status'):
        qs = qs.filter(status=serializers.ChoiceField(choices=['pending', 'reviewed', 'actioned', 'dismissed', 'resolved']).run_validation(params['status']))
    report_type = params.get('type')
    if report_type == 'message':
        qs = qs.filter(message__isnull=False)
    elif report_type in ('pod', 'task'):
        qs = qs.filter(task__isnull=False, message__isnull=True)
    elif report_type == 'user':
        qs = qs.filter(reported_user__isnull=False, message__isnull=True, task__isnull=True)
    elif report_type == 'group':
        qs = qs.filter(group__isnull=False, reported_user__isnull=True, message__isnull=True, task__isnull=True)
    elif report_type:
        raise ValidationError({'type': 'Choose group, user, message or pod.'})
    return qs


def report_review_values(request):
    review_status = serializers.ChoiceField(choices=['pending', 'reviewed', 'actioned', 'dismissed']).run_validation(request.data.get('status'))
    notes = serializers.CharField(allow_blank=True, max_length=10000).run_validation(request.data.get('notes', ''))
    return review_status, notes, request.data.get('action'), request.data.get('reason') or notes


def validated(cls, request, **kwargs):
    serializer = cls(data=request.data, context={'request': request}, **kwargs)
    serializer.is_valid(raise_exception=True)
    return serializer.validated_data


class CommunityGroupViewSet(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = GroupSerializer
    pagination_class = CommunityPagination

    def get_queryset(self):
        if not active_user(self.request.user):
            return CommunityGroup.objects.none()
        qs = CommunityGroup.objects.select_related('category', 'creator', 'conversation').prefetch_related('creator__awards')
        if not is_internal(self.request.user):
            if any(key in self.request.query_params for key in ('min_reports', 'max_reports')) or 'report_count' in self.request.query_params.get('ordering', ''):
                raise PermissionDenied('Report inventory filters are restricted to internal administrators.')
            excluded = CommunityMembership.objects.filter(user=self.request.user, state__in=['removed', 'banned']).values('group_id')
            qs = qs.filter(Q(status='active') | Q(memberships__user=self.request.user, memberships__state__in=['active', 'left'])).exclude(id__in=excluded).distinct()
            if self.action == 'list' and self.request.query_params.get('status') != 'deleted':
                qs = qs.exclude(status='deleted')
        if self.request.query_params.get('membership') == 'joined':
            qs = qs.filter(memberships__user=self.request.user, memberships__state='active')
        return filter_group_inventory(qs, self.request.query_params if self.action == 'list' else {})

    def list(self, request):
        page = self.paginate_queryset(self.get_queryset())
        return self.get_paginated_response(self.get_serializer(page, many=True).data)

    def retrieve(self, request, pk=None):
        return Response(self.get_serializer(self.get_object()).data)

    def create(self, request):
        if not can_create_group(request.user):
            raise PermissionDenied('Only internal admins and explicitly approved creators may create groups.')
        data = validated(GroupWriteSerializer, request)
        group = create_group(request.user, data)
        return Response(self.get_serializer(group).data, status=status.HTTP_201_CREATED)

    @transaction.atomic
    def partial_update(self, request, pk=None):
        group = self.get_object()
        if not can_manage_group(group, request.user):
            raise PermissionDenied()
        group = CommunityGroup.objects.select_for_update().get(pk=group.pk)
        serializer = GroupWriteSerializer(group, data=request.data, partial=True, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        if 'name' in serializer.validated_data:
            group.conversation.name = group.name
            group.conversation.save(update_fields=['name', 'updated_at'])
        audit(request.user, 'group.updated', group, metadata={'fields': list(serializer.validated_data)})
        notify(group.memberships.filter(state='active').values_list('user_id', flat=True),
               'community_group_updated', {'group_id': group.id, 'fields': list(serializer.validated_data)})
        return Response(self.get_serializer(group).data)

    @action(detail=False, methods=['get'], url_path='context')
    def context(self, request):
        invites = CommunityInvite.objects.filter(user=request.user, status='pending', expires_at__gt=timezone.now(), group__status='active').select_related('group')
        task_invites = CommunityTask.objects.filter(invitations__user=request.user, invitations__status='pending',
                                                    invitation_deadline__gt=timezone.now(), status='active').select_related('goal', 'group', 'goal__conversation')
        return Response({'is_internal': is_internal(request.user), 'can_create': can_create_group(request.user),
                         'categories': CategorySerializer(CommunityCategory.objects.all(), many=True).data,
                         'invitations': [{'id': i.id, 'group_id': i.group_id, 'group_name': i.group.name, 'role': i.role,
                                          'token': str(i.token), 'expires_at': i.expires_at} for i in invites],
                         'task_invitations': CommunityTaskSerializer(task_invites, many=True, context={'request': request}).data})

    @action(detail=True, methods=['get', 'post'])
    def members(self, request, pk=None):
        group = self.get_object()
        if request.method == 'POST':
            if not can_manage_group(group, request.user):
                raise PermissionDenied('Only group admins can manage membership.')
            data = validated(MemberActionSerializer, request)
            result = manage_group_member(group, request.user, **data)
            if isinstance(result, CommunityInvite):
                return Response({'id': result.id, 'user': user_data(result.user, request), 'role': result.role,
                                 'state': 'invited', 'token': str(result.token), 'expires_at': result.expires_at}, status=201)
            return Response(member_data(result, request))
        if not can_read_group(group, request.user):
            raise PermissionDenied()
        state = serializers.ChoiceField(choices=['active', 'pending', 'left', 'removed', 'banned', 'rejected']).run_validation(request.query_params.get('state', 'active'))
        manager = can_moderate_group(group, request.user)
        if state != 'active' and not manager:
            raise PermissionDenied('Only group moderators may inspect inactive memberships.')
        members = group.memberships.filter(state=state).select_related('user').prefetch_related('user__awards')
        if not manager:
            members = members.filter(user__is_active=True, user__deleted=False)
        own = group_membership(group, request.user)
        if own and own.state == 'left':
            members = members.filter(joined_at__lte=own.left_at)
        data = [member_data(m, request) for m in members]
        if not can_moderate_group(group, request.user):
            for member in data:
                member.pop('misconduct')
                member.pop('inactivity_review')
        return Response(data)

    @action(detail=True, methods=['post'])
    def join(self, request, pk=None):
        group = self.get_object()
        join_group(group, request.user, request.data.get('token'))
        return Response(self.get_serializer(group).data)

    @action(detail=True, methods=['post'])
    def leave(self, request, pk=None):
        group = self.get_object()
        data = validated(LeaveSerializer, request)
        leave_group(group, request.user, data['reason'], data.get('feedback', ''))
        return Response(self.get_serializer(group).data)

    @action(detail=True, methods=['get', 'post'])
    def requests(self, request, pk=None):
        group = self.get_object()
        if not can_manage_group(group, request.user):
            raise PermissionDenied()
        if request.method == 'POST':
            membership = decide_group_request(group, request.user, **validated(DecisionSerializer, request))
            return Response(member_data(membership, request))
        return Response([member_data(m, request) for m in group.memberships.filter(state='pending').select_related('user').prefetch_related('user__awards')])

    @action(detail=True, methods=['get', 'post'])
    def invitations(self, request, pk=None):
        group = self.get_object()
        if not can_manage_group(group, request.user):
            raise PermissionDenied('Only group admins can manage invitations.')
        if request.method == 'POST':
            serializers.ChoiceField(choices=['revoke']).run_validation(request.data.get('action'))
            raw_id = request.data.get('invitation_id')
            if isinstance(raw_id, bool):
                raise ValidationError({'invitation_id': 'A valid invitation ID is required.'})
            invitation_id = serializers.IntegerField(min_value=1).run_validation(raw_id)
            invitation = revoke_group_invitation(group, request.user, invitation_id)
            return Response(group_invitation_data(invitation, request))
        invitations = group.invitations.filter(status='pending', expires_at__gt=timezone.now()).select_related(
            'user', 'invited_by').prefetch_related('user__awards', 'invited_by__awards').order_by('-created_at', '-pk')
        page = self.paginate_queryset(invitations)
        return self.get_paginated_response([group_invitation_data(invitation, request) for invitation in page])

    @action(detail=True, methods=['post'], url_path='invite-link')
    def invite_link(self, request, pk=None):
        group = self.get_object()
        if not can_manage_group(group, request.user) or group.status != 'active':
            raise PermissionDenied()
        invitation = CommunityInvite.objects.create(group=group, invited_by=request.user, expires_at=timezone.now() + timedelta(days=7))
        base = getattr(settings, 'PADLUPP_APP_URL', 'https://app.padlupp.com').rstrip('/')
        return Response({'id': invitation.id, 'url': f'{base}/community?group={group.id}&invite={invitation.token}',
                         'token': str(invitation.token), 'expires_at': invitation.expires_at})

    @action(detail=True, methods=['post'], url_path='respond-invitation')
    def respond_invitation(self, request, pk=None):
        group = self.get_object()
        if request.data.get('decision') == 'accept':
            join_group(group, request.user, request.data.get('token'))
        elif request.data.get('decision') == 'decline':
            group.invitations.filter(user=request.user, status='pending').update(status='declined')
        else:
            raise ValidationError({'decision': 'Choose accept or decline.'})
        return Response(self.get_serializer(group).data)

    @action(detail=True, methods=['post'])
    def lifecycle(self, request, pk=None):
        group = set_group_status(self.get_object(), request.user, **validated(LifecycleSerializer, request))
        return Response(self.get_serializer(group).data)

    @action(detail=True, methods=['get'])
    def resources(self, request, pk=None):
        group = self.get_object()
        if not can_read_group(group, request.user):
            raise PermissionDenied()
        from .serializers import MessageSerializer
        from .message_models import MessagePin
        resource_type = request.query_params.get('type', 'media')
        qs = visible_messages(Message.objects.filter(conversation=group.conversation, recalled_at__isnull=True), request.user, resources=True)
        # Per-user hiding must apply to all surfaces, not only chat.
        from .community_messaging import visible_resource_messages
        qs = visible_resource_messages(qs, request.user)
        if resource_type == 'media':
            qs = qs.filter(Q(attachment_mime__startswith='image/') | Q(attachment_mime__startswith='video/')).exclude(attachment='')
        elif resource_type == 'files':
            qs = qs.exclude(attachment='').exclude(attachment__isnull=True).exclude(Q(attachment_mime__startswith='image/') | Q(attachment_mime__startswith='video/'))
        elif resource_type == 'links':
            qs = qs.filter(Q(text__icontains='https://') | Q(text__icontains='http://'))
        elif resource_type == 'pins':
            qs = qs.filter(id__in=MessagePin.objects.values('message_id'))
        else:
            raise ValidationError({'type': 'Choose media, files, links or pins.'})
        page = self.paginate_queryset(qs.select_related('sender', 'reply_to_message').order_by('-created_at', '-id'))
        return self.get_paginated_response(MessageSerializer(page, many=True, context={'request': request, 'resources': True}).data)

    @action(detail=True, methods=['get'], url_path='audit')
    def audit_log(self, request, pk=None):
        group = self.get_object()
        if not can_moderate_group(group, request.user):
            raise PermissionDenied()
        page = self.paginate_queryset(group.audit.select_related('actor').prefetch_related('actor__awards'))
        return self.get_paginated_response([audit_data(a, request) for a in page])

    @action(detail=True, methods=['post'])
    def report(self, request, pk=None):
        group = self.get_object()
        report = CommunityReport.objects.create(reporter=request.user, group=group, **validated(ReportSerializer, request))
        audit(request.user, 'group.reported', group, report.reason, metadata={'report_id': report.id})
        return Response({'id': report.id, 'status': report.status}, status=201)

    def _reports(self, group):
        return (CommunityReport.objects.filter(group=group)
                .filter(Q(message__isnull=True) | Q(message__conversation=group.conversation))
                .filter(Q(task__isnull=True) | Q(task__group=group))
                .select_related('reporter', 'reported_user', 'reviewer', 'message', 'task')
                .prefetch_related('reporter__awards', 'reported_user__awards', 'reviewer__awards'))

    @action(detail=True, methods=['get'])
    def reports(self, request, pk=None):
        group = self.get_object()
        if not can_moderate_group(group, request.user):
            raise PermissionDenied()
        import_content_reports(group)
        qs = filter_reports(self._reports(group), request.query_params).order_by('-created_at', '-id')
        page = self.paginate_queryset(qs)
        return self.get_paginated_response([report_data(report, request, group) for report in page])

    @action(detail=True, methods=['post'], url_path='review-report')
    @transaction.atomic
    def review_report(self, request, pk=None):
        group = self.get_object()
        if not can_moderate_group(group, request.user):
            raise PermissionDenied()
        report_id = serializers.IntegerField(min_value=1).run_validation(request.data.get('report_id'))
        report = get_object_or_404(self._reports(group), pk=report_id)
        review_status, notes, moderation_action, reason = report_review_values(request)
        if moderation_action:
            reason = require_reason(reason)
            if moderation_action == 'remove_message' and report.message_id:
                from .community_messaging import delete_selection
                delete_selection(request.user, [report.message_id], 'everyone', reason)
            elif moderation_action in ('freeze_task', 'archive_task', 'delete_task') and report.task_id and report.task.group_id == group.id:
                if not can_manage_group(group, request.user):
                    raise PermissionDenied('Only group admins can change a task lifecycle.')
                set_task_status(report.task, request.user, {'freeze_task': 'frozen', 'archive_task': 'archived', 'delete_task': 'deleted'}[moderation_action], reason)
            else:
                raise ValidationError({'action': 'This action is not permitted for a group-scoped report.'})
        from .community_messaging import set_report_review
        report = set_report_review(report, request.user, review_status, notes, reason)
        return Response(report_data(report, request, group))

    @action(detail=True, methods=['get'], url_path=r'reports/(?P<report_id>\d+)/evidence')
    def report_evidence(self, request, pk=None, report_id=None):
        group = self.get_object()
        if not can_moderate_group(group, request.user):
            raise PermissionDenied()
        report = get_object_or_404(self._reports(group), pk=report_id, status__in=['pending', 'reviewed'], message__isnull=False)
        from .community_messaging import visible_resource_messages
        message = get_object_or_404(visible_resource_messages(Message.objects.filter(pk=report.message_id), request.user))
        from .serializers import MessageSerializer
        data = MessageSerializer(message, context={'request': request, 'resources': True}).data
        data['reply_to'] = None
        return Response(data)

    @action(detail=True, methods=['post'])
    def preferences(self, request, pk=None):
        member = group_membership(self.get_object(), request.user)
        if not member or member.state != 'active':
            raise PermissionDenied()
        value = serializers.BooleanField().run_validation(request.data.get('notifications_muted'))
        member.notifications_muted = value
        member.save(update_fields=['notifications_muted', 'updated_at'])
        return Response({'notifications_muted': value})

    @action(detail=True, methods=['get', 'post'], url_path='inactivity-reviews')
    def inactivity_reviews(self, request, pk=None):
        group = self.get_object()
        if not can_manage_group(group, request.user):
            raise PermissionDenied()
        return inactivity_response(request, group=group)


class CommunityTaskViewSet(viewsets.GenericViewSet):
    serializer_class = CommunityTaskSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = CommunityPagination

    @action(detail=True, methods=['get'])
    def members(self, request, pk=None):
        task = self.get_object()
        from .community_access import can_access_goal
        if not can_access_goal(task.goal, request.user):
            raise PermissionDenied()
        manager = can_manage_task(task, request.user)
        members = task.memberships.filter(state='active').select_related('user').prefetch_related('user__awards')
        if not manager:
            members = members.filter(user__is_active=True, user__deleted=False)
        own = task_membership(task, request.user)
        if own and own.state == 'left' and not is_internal(request.user):
            members = members.filter(joined_at__lte=own.left_at)
        data = [member_data(member, request) for member in members]
        if not manager:
            for member in data:
                member.pop('misconduct')
                member.pop('inactivity_review')
        return Response(data)

    def get_queryset(self):
        user = self.request.user
        qs = CommunityTask.objects.select_related('goal', 'goal__conversation', 'group', 'creator')
        if not active_user(user):
            return qs.none()
        if not is_internal(user):
            access = Q(memberships__user=user, memberships__state__in=['active', 'pending']) | Q(invitations__user=user, invitations__status='pending', invitation_deadline__gt=timezone.now())
            # Apply all membership-history boundaries before list/retrieve, not
            # only when a group filter happens to be supplied by the client.
            for member in user.community_memberships.filter(state__in=['active', 'left']).prefetch_related('periods'):
                for index, period in enumerate(member.periods.order_by('joined_at', 'id')):
                    segment = Q(group_id=member.group_id)
                    if index:
                        segment &= Q(created_at__gte=period.joined_at)
                    if period.ended_at:
                        segment &= Q(created_at__lte=period.ended_at)
                    access |= segment
            for member in user.community_task_memberships.filter(state='left'):
                access |= Q(id=member.task_id, created_at__lte=member.left_at)
            allowed = CommunityTask.objects.filter(access).values('id')
            qs = qs.filter(id__in=allowed)
            removed = CommunityTask.objects.filter(memberships__user=user, memberships__state__in=['removed', 'banned']).values('id')
            qs = qs.exclude(id__in=removed)
        if self.request.query_params.get('group'):
            group_id = serializers.IntegerField(min_value=1).run_validation(self.request.query_params['group'])
            qs = qs.filter(group_id=group_id)
            group = get_object_or_404(CommunityGroup, pk=group_id)
            if not can_read_group(group, user):
                raise PermissionDenied()
            membership = group_membership(group, user)
            if membership and membership.state == 'left' and not is_internal(user):
                qs = qs.filter(created_at__lte=membership.left_at)
        if self.request.query_params.get('status'):
            qs = qs.filter(status=self.request.query_params['status'])
        if self.request.query_params.get('invitations') == 'pending':
            qs = qs.filter(invitations__user=user, invitations__status='pending')
        return qs.distinct().order_by('-created_at', '-id')

    def list(self, request):
        page = self.paginate_queryset(self.get_queryset())
        return self.get_paginated_response(self.get_serializer(page, many=True).data)

    def retrieve(self, request, pk=None):
        return Response(self.get_serializer(self.get_object()).data)

    @action(detail=True, methods=['get'])
    def cover(self, request, pk=None):
        task = self.get_object()
        if not task.cover:
            raise NotFound()
        from .community_messaging import protected_response
        import mimetypes
        mime = mimetypes.guess_type(task.cover.name)[0] or 'application/octet-stream'
        return protected_response(task.cover, task.cover.name.rsplit('/', 1)[-1], mime)

    def create(self, request):
        data = validated(TaskWriteSerializer, request)
        task, created = create_task(request.user, dict(data))
        return Response(self.get_serializer(task).data, status=201 if created else 200)

    @transaction.atomic
    def partial_update(self, request, pk=None):
        task = CommunityTask.objects.select_for_update().select_related('goal').get(pk=self.get_object().pk)
        if not can_manage_task(task, request.user) or task.status != 'active':
            raise PermissionDenied('Only an active pod admin may edit an active task.')
        serializer = TaskPatchSerializer(data=request.data, context={'request': request, 'task': task})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        old_cadence = (task.goal.checkin_frequency, task.custom_interval_days if task.goal.checkin_frequency == 'CUSTOM' else None)
        for field in ('title', 'description', 'checkin_frequency'):
            if field in data:
                setattr(task.goal, field, data[field])
        task.goal.save(update_fields=['title', 'description', 'checkin_frequency', 'updated_at'])
        for field in ('visibility', 'custom_interval_days'):
            if field in data:
                setattr(task, field, data[field])
        new_cadence = (task.goal.checkin_frequency, task.custom_interval_days if task.goal.checkin_frequency == 'CUSTOM' else None)
        if new_cadence != old_cadence:
            task.checkin_schedule_effective_from = max(task.goal.start_date or timezone.localdate(), timezone.localdate() + timedelta(days=1))
        task.save()
        if 'title' in data:
            conversation = task.goal.conversation
            conversation.name = task.goal.title
            conversation.save(update_fields=['name', 'updated_at'])
            # The linked task supplies current details; its original chat post
            # stays immutable, including in read-only groups and report evidence.
        if new_cadence != old_cadence:
            # Keep submitted evidence and today's already-issued cycle; replace
            # only unsubmitted future slots when the cadence changes.
            task.goal.checkins.filter(submitted_at__isnull=True, status='pending', scheduled_for__gt=timezone.localdate()).filter(
                Q(evidence='') | Q(evidence__isnull=True)).delete()
            generate_task_cycles(task)
        audit(request.user, 'task.settings_changed', task, metadata={'fields': list(data)})
        notify(task.memberships.filter(state='active').values_list('user_id', flat=True),
               'community_task_settings_changed', {'task_id': task.id, 'goal_id': task.goal_id, 'fields': list(data)})
        return Response(self.get_serializer(task).data)

    @action(detail=True, methods=['post'])
    def join(self, request, pk=None):
        task = self.get_object()
        join_task(task, request.user)
        return Response(self.get_serializer(task).data)

    @action(detail=True, methods=['post'])
    def invitations(self, request, pk=None):
        user_ids = serializers.ListField(child=serializers.IntegerField(min_value=1), max_length=100).run_validation(request.data.get('user_ids'))
        task = self.get_object()
        invitations = invite_task_users(task, request.user, user_ids)
        return Response([{'id': i.id, 'user': user_data(i.user, request), 'status': i.status} for i in invitations])

    @action(detail=True, methods=['post'], url_path='invite-link')
    @transaction.atomic
    def invite_link(self, request, pk=None):
        task = CommunityTask.objects.select_for_update().get(pk=self.get_object().pk)
        if not can_manage_task(task, request.user):
            raise PermissionDenied()
        if enrollment_status(task) != 'open':
            raise ValidationError('Invitations are not open.')
        if request.data.get('regenerate') is True:
            task.invite_token = uuid.uuid4()
            task.save(update_fields=['invite_token', 'updated_at'])
        base = getattr(settings, 'PADLUPP_APP_URL', 'https://app.padlupp.com').rstrip('/')
        return Response({'url': f'{base}/community?pod_invite={task.invite_token}', 'token': str(task.invite_token),
                         'expires_at': task.invitation_deadline, 'approval_required': True})

    @action(detail=False, methods=['post'], url_path='join-link')
    def join_link(self, request):
        token = serializers.UUIDField().run_validation(request.data.get('token'))
        task, membership = request_task_link_join(token, request.user)
        return Response({'task_id': task.id, 'goal_id': task.goal_id, 'state': membership.state,
                         'approval_required': membership.state != 'active'})

    @action(detail=True, methods=['post'])
    def respond(self, request, pk=None):
        task = self.get_object()
        if request.data.get('decision') == 'accept':
            join_task(task, request.user, invited=True)
        elif request.data.get('decision') == 'decline':
            invitation = task.invitations.filter(user=request.user, status='pending').first()
            if not invitation:
                raise ValidationError('No pending invitation.')
            invitation.status = 'declined'
            invitation.save(update_fields=['status', 'updated_at'])
        else:
            raise ValidationError({'decision': 'Choose accept or decline.'})
        return Response(self.get_serializer(task).data)

    @action(detail=True, methods=['get', 'post'])
    def requests(self, request, pk=None):
        task = self.get_object()
        if not can_manage_task(task, request.user):
            raise PermissionDenied()
        if request.method == 'POST':
            member = decide_task_request(task, request.user, **validated(DecisionSerializer, request))
            return Response(member_data(member, request))
        return Response([member_data(m, request) for m in task.memberships.filter(state='pending').select_related('user').prefetch_related('user__awards')])

    @action(detail=True, methods=['post'])
    def lifecycle(self, request, pk=None):
        task = set_task_status(self.get_object(), request.user, **validated(LifecycleSerializer, request))
        return Response(self.get_serializer(task).data)

    @action(detail=True, methods=['post'])
    @transaction.atomic
    def enrollment(self, request, pk=None):
        task = CommunityTask.objects.select_for_update().get(pk=self.get_object().pk)
        if not can_manage_task(task, request.user):
            raise PermissionDenied()
        closed = serializers.BooleanField().run_validation(request.data.get('closed'))
        if not closed and (task.status != 'active' or task.invitation_deadline <= timezone.now()):
            raise ValidationError('Expired or inactive enrollment cannot be reopened.')
        task.enrollment_closed = closed
        task.save(update_fields=['enrollment_closed', 'updated_at'])
        audit(request.user, 'task.enrollment_changed', task, metadata={'closed': closed})
        return Response(self.get_serializer(task).data)

    @action(detail=True, methods=['post'])
    def leave(self, request, pk=None):
        task = self.get_object()
        data = validated(LeaveSerializer, request)
        leave_task(task, request.user, data['reason'], data.get('transfer_to'), feedback=data.get('feedback', ''))
        return Response(self.get_serializer(task).data)

    @action(detail=True, methods=['get', 'post'])
    def members(self, request, pk=None):
        task = self.get_object()
        if not can_manage_task(task, request.user):
            raise PermissionDenied()
        if request.method == 'GET':
            return Response([member_data(m, request) for m in task.memberships.filter(state='active').select_related('user')])
        data = validated(MemberActionSerializer, request)
        if data['action'] == 'remove':
            member = leave_task(task, request.user, data['reason'], remove_user=data['user'])
        elif data['action'] == 'role':
            member = task_membership(task, data['user'])
            if not member or member.state != 'active' or data['role'] not in ('admin', 'member'):
                raise ValidationError('Choose an active member and a pod admin/member role.')
            if member.user_id == task.goal.user_id and data['role'] != 'admin':
                raise ValidationError('The owner must remain an admin.')
            member.role = data['role']
            member.save(update_fields=['role', 'updated_at'])
            task.goal.goal_memberships.filter(user=member.user).update(role=member.role)
            audit(request.user, 'task.role_changed', task, metadata={'user_id': member.user_id, 'role': member.role})
        else:
            raise ValidationError('Use invitations to invite members; pods support role and remove actions here.')
        return Response(member_data(member, request))

    @action(detail=True, methods=['get', 'post'], url_path='inactivity-reviews')
    def inactivity_reviews(self, request, pk=None):
        task = self.get_object()
        if not can_manage_task(task, request.user):
            raise PermissionDenied()
        return inactivity_response(request, task=task)

    @action(detail=True, methods=['post'])
    @transaction.atomic
    def limits(self, request, pk=None):
        if not is_internal(request.user):
            raise PermissionDenied()
        task = CommunityTask.objects.select_for_update().get(pk=self.get_object().pk)
        reason = require_reason(request.data.get('reason'))
        if 'member_limit' in request.data:
            limit = serializers.IntegerField(min_value=1, max_value=10000).run_validation(request.data['member_limit'])
            if limit < task.memberships.filter(state='active').count():
                raise ValidationError('The limit cannot be below the current active membership.')
            task.member_limit = limit
        if 'target_date' in request.data:
            end = serializers.DateField().run_validation(request.data['target_date'])
            if end < task.goal.start_date:
                raise ValidationError('The deadline cannot be before the start date.')
            task.goal.target_date = end
            task.goal.save(update_fields=['target_date', 'updated_at'])
        task.limits_approved_by, task.limits_approval_reason = request.user, reason
        task.save()
        audit(request.user, 'task.limits_approved', task, reason, metadata={'member_limit': task.member_limit, 'target_date': task.goal.target_date.isoformat()})
        return Response(self.get_serializer(task).data)

    @action(detail=True, methods=['post'])
    def report(self, request, pk=None):
        task = self.get_object()
        report = CommunityReport.objects.create(reporter=request.user, group=task.group, task=task, **validated(ReportSerializer, request))
        return Response({'id': report.id, 'status': report.status}, status=201)


class CommunityUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not active_user(request.user):
            raise PermissionDenied()
        can_pick = is_internal(request.user) or CommunityMembership.objects.filter(user=request.user, state='active', role='admin').exists() or request.user.community_task_memberships.filter(state='active', role='admin').exists()
        if not can_pick:
            raise PermissionDenied('Only group or pod managers can select invitation recipients.')
        users = get_user_model().objects.filter(is_active=True, deleted=False).prefetch_related('awards')
        search = request.query_params.get('search', '').strip()
        if search:
            users = users.filter(name__icontains=search)
        paginator = CommunityPagination()
        page = paginator.paginate_queryset(users.order_by('name', 'id'), request, view=self)
        return paginator.get_paginated_response([user_data(u, request) for u in page])


class CommunityMemberMessageView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, user_id):
        actor = request.user
        if actor.id == user_id:
            raise ValidationError('Choose another member to message.')
        # Lock in a stable order so repeated clicks and concurrent cross-opens
        # cannot create duplicate conversations for the same pair.
        users = list(get_user_model().objects.select_for_update().filter(pk__in=[actor.id, user_id]).order_by('pk'))
        target = next((u for u in users if u.id == user_id), None)
        current = next((u for u in users if u.id == actor.id), None)
        if not active_user(current) or not active_user(target):
            raise PermissionDenied('This member is unavailable.')
        if UserBlock.objects.filter(Q(blocker=actor, blocked=target) | Q(blocker=target, blocked=actor)).exists():
            raise PermissionDenied('This conversation is unavailable.')
        group_id, task_id, goal_id = (request.data.get(key) for key in ('group_id', 'task_id', 'goal_id'))
        if (group_id is not None and (task_id is not None or goal_id is not None)) or all(value is None for value in (group_id, task_id, goal_id)):
            raise ValidationError('Supply a group_id, or a task_id/goal_id identifying the shared pod.')
        key = 'group_id' if group_id is not None else 'task_id' if task_id is not None else 'goal_id'
        source_id = serializers.IntegerField(min_value=1).run_validation(request.data[key])
        if group_id is not None:
            group = get_object_or_404(CommunityGroup, pk=source_id)
            if group.memberships.filter(user_id__in=[actor.id, target.id], state='active').count() != 2:
                raise PermissionDenied('Both users must be active members of this group.')
        else:
            if task_id is not None:
                task = get_object_or_404(CommunityTask, pk=source_id)
                if goal_id is not None and task.goal_id != serializers.IntegerField(min_value=1).run_validation(goal_id):
                    raise ValidationError('The task and goal must identify the same pod.')
                goal = task.goal
            else:
                goal = get_object_or_404(Goal, pk=source_id)
                task = getattr(goal, 'community_task', None)
            if task:
                mutual = task.memberships.filter(user_id__in=[actor.id, target.id], state='active').count() == 2
            else:
                mutual = goal.goal_memberships.filter(user_id__in=[actor.id, target.id]).count() == 2
            if not mutual:
                raise PermissionDenied('Both users must be active members of this pod.')
        conversation = (Conversation.objects.annotate(member_total=Count('members', distinct=True))
                        .filter(is_group=False, goal__isnull=True, member_total=2)
                        .filter(members=actor).filter(members=target).order_by('id').first())
        if not conversation:
            conversation = Conversation.objects.create(is_group=False)
            ConversationMembership.objects.bulk_create([
                ConversationMembership(conversation=conversation, user=actor, added_by=actor),
                ConversationMembership(conversation=conversation, user=target, added_by=actor),
            ])
        ConversationMembership.objects.filter(conversation=conversation, user=actor).update(archived_at=None)
        return Response({'conversation_id': conversation.id})


class CommunityHQViewSet(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    pagination_class = CommunityPagination

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if not is_internal(request.user):
            # No distinction between a hidden internal endpoint and absent data.
            raise NotFound()

    @action(detail=False, methods=['get'])
    def overview(self, request):
        groups = CommunityGroup.objects.select_related('creator', 'category', 'conversation').prefetch_related('creator__awards').order_by('-created_at')
        groups = filter_group_inventory(groups, request.query_params)
        # Include pre-existing individual-chat reports without making private
        # conversations globally accessible to ordinary moderators.
        import_content_reports()
        reports = CommunityReport.objects.select_related('reporter', 'reported_user', 'reviewer', 'message', 'task').prefetch_related(
            'reporter__awards', 'reported_user__awards', 'reviewer__awards').order_by('-created_at')
        if request.query_params.get('report_status'):
            reports = reports.filter(status=request.query_params['report_status'])
        evidence = GoalCheckin.objects.filter(goal__community_task__isnull=False).exclude(evidence='').exclude(evidence__isnull=True).select_related('user', 'goal').order_by('-submitted_at')[:100]
        from .serializers import GoalCheckinSerializer
        return Response({'groups': GroupSerializer(groups[:200], many=True, context={'request': request}).data,
                         'reports': [report_data(r, request) for r in reports[:200]],
                         'audit': [audit_data(a, request) for a in CommunityAudit.objects.select_related('actor').prefetch_related('actor__awards')[:200]],
                         'creators': [{'user': user_data(a.user, request), 'approved': a.approved} for a in CommunityCreatorApproval.objects.select_related('user').prefetch_related('user__awards')],
                         'evidence': GoalCheckinSerializer(evidence, many=True, context={'request': request}).data})

    @action(detail=False, methods=['get'])
    def users(self, request):
        qs = get_user_model().objects.filter(deleted=False).prefetch_related('awards').annotate(
            group_creation_approved=Exists(CommunityCreatorApproval.objects.filter(user_id=OuterRef('pk'), approved=True)),
        )
        if request.query_params.get('search'):
            qs = qs.filter(name__icontains=request.query_params['search'])
        page = self.paginate_queryset(qs.order_by('name', 'id'))
        return self.get_paginated_response([
            {**user_data(u, request), 'group_creation_approved': u.group_creation_approved} for u in page
        ])

    @action(detail=False, methods=['get'])
    def evidence(self, request):
        from .serializers import GoalCheckinSerializer
        qs = (GoalCheckin.objects.filter(goal__community_task__isnull=False)
              .exclude(evidence='').exclude(evidence__isnull=True)
              .select_related('user', 'goal', 'reviewer').order_by('-submitted_at', '-id'))
        page = self.paginate_queryset(qs)
        return self.get_paginated_response(GoalCheckinSerializer(page, many=True, context={'request': request}).data)

    @action(detail=False, methods=['get'], url_path='groups')
    def group_inventory(self, request):
        qs = filter_group_inventory(CommunityGroup.objects.select_related('category', 'creator', 'conversation').prefetch_related('creator__awards'), request.query_params)
        page = self.paginate_queryset(qs)
        return self.get_paginated_response(GroupSerializer(page, many=True, context={'request': request}).data)

    @action(detail=False, methods=['get'])
    def reports(self, request):
        import_content_reports()
        qs = CommunityReport.objects.select_related('reporter', 'reported_user', 'reviewer', 'message', 'task').prefetch_related(
            'reporter__awards', 'reported_user__awards', 'reviewer__awards').order_by('-created_at', '-id')
        qs = filter_reports(qs, request.query_params)
        for key in ('group', 'task', 'reported_user'):
            if request.query_params.get(key):
                qs = qs.filter(**{key + '_id': serializers.IntegerField(min_value=1).run_validation(request.query_params[key])})
        page = self.paginate_queryset(qs)
        return self.get_paginated_response([report_data(r, request) for r in page])

    @action(detail=False, methods=['get'], url_path='audit')
    def audit_log(self, request):
        qs = CommunityAudit.objects.select_related('actor').prefetch_related('actor__awards').all()
        if request.query_params.get('action'):
            qs = qs.filter(action=request.query_params['action'])
        for key in ('group', 'task', 'actor'):
            if request.query_params.get(key):
                qs = qs.filter(**{key + '_id': serializers.IntegerField(min_value=1).run_validation(request.query_params[key])})
        page = self.paginate_queryset(qs)
        return self.get_paginated_response([audit_data(a, request) for a in page])

    @action(detail=False, methods=['get'], url_path='inactivity-reviews')
    def inactivity_reviews(self, request):
        qs = CommunityInactivityReview.objects.filter(resolved=False).select_related('user').prefetch_related('user__awards').order_by('-created_at', '-id')
        page = self.paginate_queryset(qs)
        return self.get_paginated_response([{'id': r.id, 'user': user_data(r.user, request), 'group_id': r.group_id,
                                            'task_id': r.task_id, 'last_login_at': r.last_login_at} for r in page])

    @action(detail=False, methods=['post'], url_path='review-inactivity')
    @transaction.atomic
    def review_inactivity(self, request):
        review = get_object_or_404(CommunityInactivityReview.objects.select_for_update(), pk=request.data.get('review_id'), resolved=False)
        decision = serializers.ChoiceField(choices=['retain', 'remove']).run_validation(request.data.get('decision'))
        resolve_inactivity_review(review, request.user, decision, request.data.get('reason'), request.data.get('transfer_to'))
        return Response({'id': review.id, 'resolved': True, 'decision': decision})

    @action(detail=False, methods=['post'], url_path='approve-creator')
    @transaction.atomic
    def approve_creator(self, request):
        user = get_object_or_404(get_user_model(), pk=request.data.get('user_id'), is_active=True, deleted=False)
        approved = serializers.BooleanField().run_validation(request.data.get('approved'))
        approval, _ = CommunityCreatorApproval.objects.update_or_create(user=user, defaults={'approved': approved, 'approved_by': request.user})
        audit(request.user, 'creator.approved' if approved else 'creator.revoked', approval, metadata={'user_id': user.id})
        notify([user.id], 'community_creation_permission', {'approved': approved})
        return Response({'user': user_data(user, request), 'approved': approval.approved})

    @action(detail=False, methods=['post'], url_path='review-report')
    @transaction.atomic
    def review_report(self, request):
        report = get_object_or_404(CommunityReport, pk=request.data.get('report_id'))
        review_status, notes, moderation_action, reason = report_review_values(request)
        if moderation_action:
            reason = require_reason(reason)
            if moderation_action in ('freeze_group', 'archive_group', 'delete_group') and report.group_id:
                set_group_status(report.group, request.user, {'freeze_group': 'frozen', 'archive_group': 'archived', 'delete_group': 'deleted'}[moderation_action], reason)
            elif moderation_action in ('freeze_task', 'archive_task', 'delete_task') and report.task_id:
                set_task_status(report.task, request.user, {'freeze_task': 'frozen', 'archive_task': 'archived', 'delete_task': 'deleted'}[moderation_action], reason)
            elif moderation_action in ('warn_user', 'ban_user', 'deactivate_user') and report.reported_user_id:
                self._moderate_user(request.user, report.reported_user, moderation_action.removesuffix('_user'), reason)
            elif moderation_action == 'remove_message' and report.message_id:
                from .community_messaging import delete_selection
                delete_selection(request.user, [report.message_id], 'everyone', reason)
            else:
                raise ValidationError({'action': 'This report does not support the requested action.'})
        from .community_messaging import set_report_review
        report = set_report_review(report, request.user, review_status, notes, reason)
        return Response(report_data(report, request))

    def _moderate_user(self, actor, user, moderation_action, reason):
        user = get_user_model().objects.select_for_update().get(pk=user.pk)
        if user.id == actor.id or (user.is_superuser and not actor.is_superuser):
            raise PermissionDenied('Platform-owner recovery must be preserved.')
        if moderation_action in ('ban', 'deactivate', 'restrict'):
            groups = list(CommunityGroup.objects.select_for_update().filter(
                memberships__user=user, memberships__state='active', memberships__role='admin').order_by('id'))
            counts = {group.id: group_admin_count(group) for group in groups}
            user.is_active = False
            user.save(update_fields=['is_active', 'updated_at'])
            from knox.models import AuthToken
            AuthToken.objects.filter(user=user).delete()
            for group in groups:
                notify_admin_shortage(group, counts[group.id])
        elif moderation_action in ('unban', 'reactivate'):
            user.is_active = True
            user.save(update_fields=['is_active', 'updated_at'])
        elif moderation_action not in ('warn', 'flag'):
            raise ValidationError({'action': 'Choose warn, flag, restrict, ban, deactivate, unban or reactivate.'})
        audit(actor, 'user.' + moderation_action, user, reason)
        if moderation_action in ('warn', 'flag', 'unban', 'reactivate'):
            notify([user.id], 'community_account_notice', {'action': moderation_action, 'reason': reason})
        return user

    @action(detail=False, methods=['post'], url_path='moderate-user')
    @transaction.atomic
    def moderate_user(self, request):
        user = get_object_or_404(get_user_model(), pk=request.data.get('user_id'), deleted=False)
        user = self._moderate_user(request.user, user, request.data.get('action'), require_reason(request.data.get('reason')))
        return Response({'user': user_data(user, request), 'is_active': user.is_active})

    @action(detail=False, methods=['post'], url_path='delete-evidence')
    @transaction.atomic
    def delete_evidence(self, request):
        checkin = get_object_or_404(GoalCheckin.objects.select_for_update(), pk=request.data.get('checkin_id'))
        reason = require_reason(request.data.get('reason'))
        evidence = checkin.evidence
        storage, name = evidence.storage, evidence.name
        checkin.evidence = None
        checkin.evidence_deleted_at = timezone.now()
        checkin.evidence_deleted_by = request.user
        checkin.evidence_deletion_reason = reason
        checkin.save(update_fields=['evidence', 'evidence_deleted_at', 'evidence_deleted_by', 'evidence_deletion_reason', 'updated_at'])
        if name:
            transaction.on_commit(lambda: storage.delete(name))
        from .community_messaging import broadcast_message
        for message in Message.objects.filter(kind='checkin', metadata__checkin_id=checkin.id):
            message.metadata['has_evidence'] = False
            message.save(update_fields=['metadata', 'updated_at'])
            transaction.on_commit(lambda mid=message.id, cid=message.conversation_id: broadcast_message(mid, cid))
        audit(request.user, 'checkin.evidence_deleted', checkin, reason, metadata={'goal_id': checkin.goal_id})
        return Response({'id': checkin.id, 'evidence': None})


class CommunityMaintenanceView(APIView):
    authentication_classes = []
    permission_classes = [HasCronSecret]

    def post(self, request):
        count = 0
        for task in CommunityTask.objects.filter(status='active').select_related('goal', 'goal__conversation'):
            with transaction.atomic():
                task = CommunityTask.objects.select_for_update().get(pk=task.pk)
                count += generate_task_cycles(task)
        return Response({'checkins_created': count, 'memberships_flagged': review_inactive_members()})


def inactivity_response(request, **scope):
    if request.method == 'POST':
        review_id = serializers.IntegerField(min_value=1).run_validation(request.data.get('review_id'))
        review = get_object_or_404(CommunityInactivityReview, pk=review_id, **scope)
        resolve_inactivity_review(review, request.user, request.data.get('decision'), request.data.get('reason'), request.data.get('transfer_to'))
        return Response({'id': review.id, 'resolved': True})
    reviews = CommunityInactivityReview.objects.filter(resolved=False, **scope).select_related('user').prefetch_related('user__awards').order_by('created_at', 'id')
    paginator = CommunityPagination()
    page = paginator.paginate_queryset(reviews, request)
    return paginator.get_paginated_response([{'id': r.id, 'user': user_data(r.user, request),
                                             'last_login_at': r.last_login_at, 'group_id': r.group_id, 'task_id': r.task_id} for r in page])
