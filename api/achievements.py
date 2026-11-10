"""Community achievements, separate from the permanent legacy award catalog.

Reconciliation imports verifiable memberships, submissions, current confirmations,
positive reactions and comeback sequences. Historical milestone completers and pod
completion qualifications without immutable snapshots are deliberately not inferred.
"""
from dataclasses import dataclass
from datetime import date, timedelta, timezone as datetime_timezone

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .community_access import active_user, task_membership
from .community_models import CommunityInactivityReview, CommunityTask
from .models import AchievementCredit, GoalCheckin, Message, Notification, Task, UserAward
from .message_models import MessageReaction


POSITIVE_MESSAGE_EMOJIS = frozenset({'\U0001f44d', '\u2764', '\U0001f44f', '\U0001f389', '\U0001f525'})
SUBMITTED_STATUSES = frozenset({'completed', 'partial', 'blocked'})


def is_positive_emoji(value):
    # Strip presentation and skin-tone modifiers, not arbitrary substrings/ZWJ sequences.
    normalized = ''.join(char for char in value if char not in {'\ufe0e', '\ufe0f'}
                         and not '\U0001f3fb' <= char <= '\U0001f3ff')
    return normalized in POSITIVE_MESSAGE_EMOJIS


@dataclass(frozen=True)
class AchievementDefinition:
    key: str
    name: str
    description: str
    metric: str
    target: int
    extra: tuple = ()


ACHIEVEMENTS = (
    AchievementDefinition('pod_creator', 'Pod Creator', 'Create 10 Paddie Pod tasks that at least one other user joins.', 'created_pods', 10),
    AchievementDefinition('pod_magnet', 'Pod Magnet', 'Create 3 tasks with at least 75% of their capacity filled.', 'filled_pods', 3),
    AchievementDefinition('proof_in_the_pudding', 'Proof in the Pudding', 'Successfully submit 10 evidence-backed check-ins in the community.', 'evidence_checkins', 10),
    AchievementDefinition('no_ghosting', 'No Ghosting', 'Complete 3 pods without voluntarily leaving or becoming inactive for 28 days without login.', 'reliable_pods', 3),
    AchievementDefinition('accountability_ace', 'Accountability Ace', "Confirm 10 other Paddies' check-ins across at least 2 community pods.", 'confirmations', 10,
                          (('confirmation_pods', 'Community pods', 2),)),
    AchievementDefinition('hype_paddie', 'Hype Paddie', 'Give 20 positive message reactions or check-in confirmations involving at least 5 different community members.', 'positive_interactions', 20,
                          (('interaction_members', 'Different members', 5),)),
    AchievementDefinition('comeback_kid', 'Comeback Kid', 'Submit 3 consecutive on-time owed check-ins in the same pod after a missed check-in.', 'comeback_checkins', 3),
    AchievementDefinition('milestone_hunter', 'Milestone Hunter', 'Complete 10 milestones across at least 3 separate community tasks.', 'completed_milestones', 10,
                          (('milestone_tasks', 'Community tasks', 3),)),
    AchievementDefinition('model_paddie', 'Model Paddie', 'Complete 10 community tasks on time, with every owed check-in in those tasks submitted on time. Honest partial or blocked check-ins count.', 'model_pods', 10),
)
ACHIEVEMENT_BY_KEY = {definition.key: definition for definition in ACHIEVEMENTS}


def _credit(user, kind, subject_type, subject_id, occurred_at, **metadata):
    credit, _ = AchievementCredit.objects.get_or_create(
        user=user, kind=kind, subject_type=subject_type, subject_id=str(subject_id),
        defaults={'occurred_at': occurred_at, 'metadata': {'version': 1, **metadata}},
    )
    return credit


def _lock_user(user):
    # Serialize evaluations without blocking unrelated PostgreSQL FK inserts.
    return get_user_model().objects.select_for_update(no_key=True).get(pk=user.pk)


def _member_at(task, user, at):
    member = task_membership(task, user)
    return member and any(period.joined_at <= at and (not period.ended_at or at <= period.ended_at)
                          for period in member.periods.all())


def _metrics(user):
    rows = list(AchievementCredit.objects.filter(user=user))
    by_kind = {}
    for row in rows:
        by_kind.setdefault(row.kind, []).append(row)
    def count(kind):
        return len(by_kind.get(kind, []))
    def distinct(kind, field):
        return len({row.metadata[field] for row in by_kind.get(kind, []) if row.metadata.get(field) is not None})
    return {
        'created_pods': count('pod_created_joined'), 'filled_pods': count('pod_capacity'),
        'evidence_checkins': count('checkin_submitted'), 'reliable_pods': count('pod_reliable'),
        'confirmations': count('checkin_confirmed'), 'confirmation_pods': distinct('checkin_confirmed', 'task_id'),
        'positive_interactions': count('positive_interaction'), 'interaction_members': distinct('positive_interaction', 'other_user_id'),
        'comeback_checkins': max((row.metadata.get('consecutive', 0) for row in by_kind.get('comeback', [])), default=0),
        'completed_milestones': count('milestone_completed'), 'milestone_tasks': distinct('milestone_completed', 'task_id'),
        'model_pods': count('pod_model'),
    }


def _requirements(definition, metrics):
    requirements = [(definition.metric, definition.name, definition.target), *definition.extra]
    return [{'key': key, 'label': label, 'current': min(metrics.get(key, 0), target), 'target': target}
            for key, label, target in requirements]


@transaction.atomic
def evaluate_achievements(user):
    if not active_user(user):
        return
    _lock_user(user)
    metrics = _metrics(user)
    for definition in ACHIEVEMENTS:
        if not all(row['current'] >= row['target'] for row in _requirements(definition, metrics)):
            continue
        _, created = UserAward.objects.get_or_create(user=user, award_key=definition.key,
                                                     defaults={'progress_snapshot': definition.target})
        if created and user.notify_on_milestones:
            Notification.objects.create(user=user, type='milestone_unlocked', payload={
                'award_key': definition.key, 'title': 'Milestone unlocked',
                'message': f'You earned the {definition.name} achievement.', 'path': '/milestones',
            })


@transaction.atomic
def record_pod_enrollment(task, *, evaluate=True):
    _lock_user(task.creator)
    now = timezone.now()
    others = task.memberships.exclude(user_id=task.creator_id).filter(periods__joined_at__lte=now)
    if others.exists():
        accepted = others.order_by('user_id').first()
        _credit(task.creator, 'pod_created_joined', 'pod', task.pk, now, task_id=task.pk,
                accepted_membership_id=accepted.pk, other_user_id=accepted.user_id)
    count = task.memberships.filter(
        Q(periods__ended_at__isnull=True) | Q(periods__ended_at__gte=now),
        state='active', periods__joined_at__lte=now).distinct().count()
    if task.status == 'active' and others.exists() and count * 4 >= task.member_limit * 3:
        _credit(task.creator, 'pod_capacity', 'pod', task.pk, now,
                task_id=task.pk, member_count=count, member_limit=task.member_limit)
    if evaluate:
        evaluate_achievements(task.creator)


def _on_time(row):
    return bool(row.status in SUBMITTED_STATUSES and row.submitted_at and
                row.submitted_at.astimezone(datetime_timezone.utc).date() <= row.scheduled_for)


def _owed_dates(task, member, at):
    from .community_services import task_due_dates
    today = at.astimezone(datetime_timezone.utc).date()
    dates = set(task.goal.checkins.filter(scheduled_for__lte=today).values_list('scheduled_for', flat=True))
    snapshots = []
    for entry in task.audit.all():
        if (entry.created_at <= at and 'checkin_due_dates' in entry.outcome and
                (entry.outcome.get('previous_status') == 'active' or
                 entry.action in ('task.settings_changed', 'task.limits_approved'))):
            snapshots.append(entry.outcome['checkin_due_dates'])
    for snapshot in snapshots:
        dates.update(date.fromisoformat(value) for value in snapshot)
    # Stopped segments are defined by their snapshots, not today's mutable schedule.
    # An active resumed/edited segment still contributes its own current obligations.
    if task.status == 'active' or not snapshots:
        dates.update(task_due_dates(task, until=today))
    periods = list(member.periods.all())
    return {due for due in dates if due <= today and any(
        period.joined_at.astimezone(datetime_timezone.utc).date() <= due <=
        min(period.ended_at or at, at).astimezone(datetime_timezone.utc).date() for period in periods)}


def _record_comeback(task, user, at):
    member = task.memberships.filter(user=user).first()
    if not member:
        return
    rows = {row.scheduled_for: row for row in task.goal.checkins.filter(
        user=user, scheduled_for__lte=at.astimezone(datetime_timezone.utc).date())}
    recovering, consecutive, best = False, 0, 0
    missed, run, best_run, best_missed = None, [], [], None
    for due in sorted(_owed_dates(task, member, at)):
        row = rows.get(due)
        if row and _on_time(row) and row.submitted_at <= at and _member_at(task, user, row.submitted_at):
            if recovering:
                consecutive += 1
                run.append(row)
                if consecutive > best:
                    best, best_run, best_missed = consecutive, run[:3], missed
        elif due < at.astimezone(datetime_timezone.utc).date() or (row and row.submitted_at):
            recovering, consecutive = True, 0
            missed, run = due, []
    if best:
        metadata = {'task_id': task.pk, 'consecutive': min(best, 3),
                    'missed_due_date': best_missed.isoformat(), 'checkin_ids': [row.pk for row in best_run],
                    'due_dates': [row.scheduled_for.isoformat() for row in best_run]}
        credit = _credit(user, 'comeback', 'pod', task.pk, at, **metadata)
        credit = AchievementCredit.objects.select_for_update().get(pk=credit.pk)
        if min(best, 3) > credit.metadata.get('consecutive', 0):
            credit.metadata = {**credit.metadata, **metadata}
            credit.occurred_at = at
            credit.save(update_fields=['metadata', 'occurred_at', 'updated_at'])


@transaction.atomic
def record_checkin_submission(checkin, *, evaluate=True, comeback=True):
    task = getattr(checkin.goal, 'community_task', None)
    if not task or checkin.status not in SUBMITTED_STATUSES or not checkin.submitted_at:
        return
    if not _member_at(task, checkin.user, checkin.submitted_at):
        return
    _lock_user(checkin.user)
    if checkin.evidence:
        _credit(checkin.user, 'checkin_submitted', 'checkin', checkin.pk, checkin.submitted_at,
                task_id=task.pk, scheduled_for=checkin.scheduled_for.isoformat(), evidence_backed=True,
                on_time=_on_time(checkin))
    if comeback:
        _record_comeback(task, checkin.user, checkin.submitted_at)
    if evaluate:
        evaluate_achievements(checkin.user)


@transaction.atomic
def record_checkin_confirmation(checkin, actor, *, evaluate=True):
    task = getattr(checkin.goal, 'community_task', None)
    at = checkin.reviewed_at
    if not task or checkin.review_status != 'confirmed' or not at or checkin.user_id == actor.pk:
        return
    if not checkin.submitted_at or at < checkin.submitted_at or not _member_at(task, actor, at):
        return
    _lock_user(actor)
    metadata = {'task_id': task.pk, 'other_user_id': checkin.user_id,
                'reviewer_id': actor.pk, 'reviewed_at': at.isoformat()}
    _credit(actor, 'checkin_confirmed', 'checkin', checkin.pk, at, **metadata)
    _credit(actor, 'positive_interaction', 'checkin', checkin.pk, at, interaction='confirmation', **metadata)
    if evaluate:
        evaluate_achievements(actor)


@transaction.atomic
def record_positive_reaction(message, actor, emoji, *, occurred_at=None, evaluate=True):
    if not is_positive_emoji(emoji) or message.sender_id == actor.pk or message.recalled_at:
        return
    if not active_user(actor):
        return
    task = getattr(message.conversation.goal, 'community_task', None) if message.conversation.goal_id else None
    group = getattr(message.conversation, 'community_group', None)
    if not task and not group:
        return
    at = occurred_at or timezone.now()
    if not occurred_at:
        from .community_messaging import can_interact
        if not can_interact(message.conversation, actor):
            return
    if task and not _member_at(task, actor, at):
        return
    if group and not group.memberships.filter(
            Q(periods__ended_at__isnull=True) | Q(periods__ended_at__gte=at),
            user=actor, periods__joined_at__lte=at).exists():
        return
    subject_type, subject_id, other_user_id = 'message', message.pk, message.sender_id
    if message.kind == Message.KIND_CHECKIN:
        checkin_id = message.metadata.get('checkin_id')
        if type(checkin_id) is not int:
            return
        checkin = GoalCheckin.objects.filter(pk=checkin_id, goal_id=message.conversation.goal_id,
                                            user_id=message.sender_id, submitted_at__isnull=False).first()
        if not checkin:
            return
        subject_type, subject_id = 'checkin', checkin.pk
    elif message.kind == Message.KIND_GOAL and group and message.metadata.get('event') == 'community_task_created':
        task_id = message.metadata.get('community_task_id')
        if type(task_id) is not int or not CommunityTask.objects.filter(pk=task_id, group=group, creator_id=message.sender_id).exists():
            return
    elif message.kind != Message.KIND_USER:
        return
    _lock_user(actor)
    _credit(actor, 'positive_interaction', subject_type, subject_id, at,
            other_user_id=other_user_id, task_id=task.pk if task else None,
            group_id=task.group_id if task else group.pk, interaction='message_reaction', emoji=emoji,
            message_id=message.pk)
    if evaluate:
        evaluate_achievements(actor)


@transaction.atomic
def record_milestone_completion(milestone, actor):
    task = getattr(milestone.goal, 'community_task', None)
    now = timezone.now()
    if not task or not (milestone.completed or milestone.status == Task.STATUS_COMPLETED):
        return
    if not active_user(actor) or not _member_at(task, actor, now):
        return
    _lock_user(actor)
    _credit(actor, 'milestone_completed', 'milestone', milestone.pk, now, task_id=task.pk, actor_id=actor.pk)
    evaluate_achievements(actor)


@transaction.atomic
def record_pod_inactivity(user, task_id, last_login, at):
    _lock_user(user)
    _credit(user, 'pod_inactive', 'pod', task_id, at,
            task_id=task_id, last_login_at=last_login.isoformat(), observed_at=at.isoformat())


def record_login_gap(user, at):
    previous = get_user_model().objects.get(pk=user.pk).last_login or user.created_at
    if previous > at - timedelta(days=28):
        return
    for member in user.community_task_memberships.filter(state='active').select_related('task'):
        record_pod_inactivity(user, member.task_id, previous, at)


@transaction.atomic
def record_pod_completion(task, actor, *, previous_status, completion_audit):
    if task.status != 'completed' or previous_status == 'completed':
        return
    if completion_audit.task_id != task.pk or completion_audit.action != 'task.completed':
        return
    completed_at = completion_audit.created_at
    due_day = task.goal.target_date
    for member in task.memberships.filter(state='active', user__is_active=True, user__deleted=False).select_related('user').prefetch_related('periods').order_by('user_id'):
        user = _lock_user(member.user)
        if not active_user(user) or not _member_at(task, user, completed_at):
            continue
        last_login = user.last_login or user.created_at
        inactive = (last_login <= completed_at - timedelta(days=28) or
                    AchievementCredit.objects.filter(user=user, kind='pod_inactive', subject_id=str(task.pk),
                                                     occurred_at__lte=completed_at).exists() or
                    CommunityInactivityReview.objects.filter(user=user, task=task, created_at__lte=completed_at).exists())
        left = task.audit.filter(action='task.left', outcome__user_id=user.pk, created_at__lte=completed_at).exists()
        metadata = {'task_id': task.pk, 'completed_at': completed_at.isoformat(),
                    'target_date': due_day.isoformat() if due_day else None, 'actor_id': actor.pk,
                    'completion_audit_id': completion_audit.pk, 'last_login_at': last_login.isoformat(),
                    'voluntary_left': left, 'inactivity_detected': inactive}
        expected = _owed_dates(task, member, completed_at)
        rows = {row.scheduled_for: row for row in task.goal.checkins.filter(user=user, scheduled_for__in=expected)}
        on_time = bool(expected) and all(due in rows and _on_time(rows[due]) and rows[due].submitted_at <= completed_at and
                                      _member_at(task, user, rows[due].submitted_at) for due in expected)
        completed_on_time = bool(due_day and completed_at.astimezone(datetime_timezone.utc).date() <= due_day)
        snapshot = _credit(user, 'pod_completed', 'pod', task.pk, completed_at,
                           reliable=not left and not inactive, model=completed_on_time and on_time,
                           owed_dates=[due.isoformat() for due in sorted(expected)], **metadata)
        if snapshot.metadata['reliable']:
            _credit(user, 'pod_reliable', 'pod', task.pk, snapshot.occurred_at, **snapshot.metadata)
        if snapshot.metadata['model']:
            _credit(user, 'pod_model', 'pod', task.pk, completed_at,
                    **snapshot.metadata)
        evaluate_achievements(user)


def _achievement_payload(definition, metrics, grants):
    grant = grants.get(definition.key)
    requirements = _requirements(definition, metrics)
    return {'key': definition.key, 'name': definition.name, 'description': definition.description,
            'current': requirements[0]['current'], 'target': definition.target,
            'eligible': grant is not None, 'earned_at': grant.unlocked_at if grant else None,
            'claimed_at': grant.claimed_at if grant else None, 'requirements': requirements}


@transaction.atomic
def reconcile_achievement_facts(user):
    """Import only provable source facts; never infer completers or past limits."""
    # Both live hooks and reconciliation acquire the user before mutable credit rows.
    _lock_user(user)
    now = timezone.now()
    for task in CommunityTask.objects.filter(creator=user).select_related('creator', 'goal'):
        record_pod_enrollment(task, evaluate=False)
    submissions = GoalCheckin.objects.filter(user=user, goal__community_task__isnull=False,
                                            submitted_at__lte=now, status__in=SUBMITTED_STATUSES)
    for checkin in submissions.exclude(evidence='').exclude(evidence__isnull=True).select_related('goal', 'user'):
        record_checkin_submission(checkin, evaluate=False, comeback=False)
    for task in CommunityTask.objects.filter(goal__checkins__user=user).distinct().select_related('goal'):
        _record_comeback(task, user, now)
    for checkin in GoalCheckin.objects.filter(reviewer=user, review_status='confirmed', reviewed_at__lte=now,
                                             goal__community_task__isnull=False).select_related('goal', 'user'):
        record_checkin_confirmation(checkin, user, evaluate=False)
    for reaction in MessageReaction.objects.filter(user=user, created_at__lte=now).select_related('message__conversation', 'message__sender'):
        record_positive_reaction(reaction.message, user, reaction.emoji, occurred_at=reaction.created_at, evaluate=False)


def achievements_payload(user):
    reconcile_achievement_facts(user)
    evaluate_achievements(user)
    grants = {row.award_key: row for row in UserAward.objects.filter(user=user)}
    metrics = _metrics(user)
    from .awards import AWARD_BY_KEY
    return {'achievements': [_achievement_payload(definition, metrics, grants) for definition in ACHIEVEMENTS],
            'legacy_awards': [{'key': key, 'name': AWARD_BY_KEY[key].title, 'unlocked_at': row.unlocked_at}
                              for key, row in grants.items() if key in AWARD_BY_KEY]}


@transaction.atomic
def claim_achievement(user, key):
    if key not in ACHIEVEMENT_BY_KEY:
        return None
    _lock_user(user)
    reconcile_achievement_facts(user)
    evaluate_achievements(user)
    grant = UserAward.objects.filter(user=user, award_key=key).first()
    if not grant:
        return None
    if grant.claimed_at is None:
        grant.claimed_at = timezone.now()
        grant.save(update_fields=['claimed_at', 'updated_at'])
    return _achievement_payload(ACHIEVEMENT_BY_KEY[key], _metrics(user), {key: grant})
