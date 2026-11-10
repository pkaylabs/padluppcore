from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.response import Response

from .achievement_serializers import AchievementCatalogSerializer, AchievementSerializer
from .achievements import ACHIEVEMENT_BY_KEY, achievements_payload, claim_achievement
from .community_access import active_user
from .serializers import DetailResponseSerializer


class AchievementViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'key'

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if not active_user(request.user):
            raise PermissionDenied('An active account is required.')

    @extend_schema(
        responses={200: AchievementCatalogSerializer},
        description='Nine ordered community achievements with server-reconciled progress. '
                    'Only verifiable history is imported; milestone completers and historical pod '
                    'qualifications without immutable snapshots are not inferred. Earned awards '
                    'appear on community profiles only after claiming.',
    )
    def list(self, request):
        return Response(achievements_payload(request.user))

    @extend_schema(
        request=None,
        parameters=[OpenApiParameter('key', OpenApiTypes.STR, OpenApiParameter.PATH, enum=[*ACHIEVEMENT_BY_KEY])],
        responses={200: AchievementSerializer, 400: DetailResponseSerializer, 409: DetailResponseSerializer, 404: DetailResponseSerializer},
    )
    @action(detail=True, methods=['post'])
    def claim(self, request, key=None):
        if key not in ACHIEVEMENT_BY_KEY:
            raise NotFound('Unknown achievement.')
        if request.data:
            raise ValidationError('Claims accept no client progress or other fields.')
        achievement = claim_achievement(request.user, key)
        if achievement is None:
            return Response({'detail': 'This achievement is not yet eligible.'}, status=status.HTTP_409_CONFLICT)
        return Response(achievement)
