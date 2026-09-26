from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from django.db import transaction
from django.db.models import Exists, OuterRef, Q
from django.utils import timezone

from padluppcore.utils.constants import StatusEnum

from .models import Goal, GoalMembership, Notification, ReferralInvite, UserAward
from .streaks import get_streak_stats


@dataclass(frozen=True)
class AwardDefinition:
    key: str
    category_key: str
    category_title: str
    title: str
    description: str
    target: int


AWARD_DEFINITIONS = (
    AwardDefinition(
        key='goal_started',
        category_key='goals',
        category_title='Goals',
        title='Started a goal',
        description='Create your first goal.',
        target=1,
    ),
    AwardDefinition(
        key='goal_completed',
        category_key='goals',
        category_title='Goals',
        title='Completed a goal',
        description='Complete a goal you own or collaborate on.',
        target=1,
    ),
    AwardDefinition(
        key='five_goals_completed',
        category_key='goals',
        category_title='Goals',
        title='Complete 5 goals',
        description='Complete five goals you own or collaborate on.',
        target=5,
    ),
    AwardDefinition(
        key='streak_3',
        category_key='streak',
        category_title='Streak',
        title='3-day streak',
        description='Stay active on Padlupp for three consecutive days.',
        target=3,
    ),
    AwardDefinition(
        key='streak_7',
        category_key='streak',
        category_title='Streak',
        title='7-day streak',
        description='Stay active on Padlupp for seven consecutive days.',
        target=7,
    ),
    AwardDefinition(
        key='streak_14',
        category_key='streak',
        category_title='Streak',
        title='14-day streak',
        description='Stay active on Padlupp for fourteen consecutive days.',
        target=14,
    ),
    AwardDefinition(
        key='successful_referral',
        category_key='referrals',
        category_title='Referrals',
        title='Referral badge',
        description='Invite someone who successfully joins Padlupp.',
        target=1,
    ),
    AwardDefinition(
        key='team_player',
        category_key='team_player',
        category_title='Team Player',
        title='Collaborated on a goal',
        description='Work on a goal with at least one other member.',
        target=1,
    ),
)

AWARD_BY_KEY = {definition.key: definition for definition in AWARD_DEFINITIONS}


def _user_goals(user):
    return Goal.objects.filter(
        Q(user=user)
        | Q(goal_memberships__user=user)
        | Q(partnership__user_a=user)
        | Q(partnership__user_b=user)
    ).distinct()


def award_progress_for_user(user) -> dict[str, int]:
    user_goals = _user_goals(user)
    completed_goals = user_goals.filter(status=StatusEnum.COMPLETED.value).count()
    other_members = GoalMembership.objects.filter(goal_id=OuterRef('pk')).exclude(user=user)
    collaborative_goals = (
        user_goals.annotate(has_other_member=Exists(other_members))
        .filter(Q(has_other_member=True) | Q(partnership__isnull=False))
        .count()
    )
    longest_streak = get_streak_stats(user)['longest_streak_count']
    successful_referrals = ReferralInvite.objects.filter(
        inviter=user,
        referred_user__isnull=False,
        accepted_at__isnull=False,
    ).count()

    return {
        'goal_started': Goal.objects.filter(user=user).count(),
        'goal_completed': completed_goals,
        'five_goals_completed': completed_goals,
        'streak_3': longest_streak,
        'streak_7': longest_streak,
        'streak_14': longest_streak,
        'successful_referral': successful_referrals,
        'team_player': collaborative_goals,
    }


def evaluate_user_awards(user, *, notify: bool = True) -> list[UserAward]:
    if not user or not getattr(user, 'pk', None):
        return []

    progress = award_progress_for_user(user)
    newly_unlocked = []
    for definition in AWARD_DEFINITIONS:
        current = progress.get(definition.key, 0)
        if current < definition.target:
            continue

        award, created = UserAward.objects.get_or_create(
            user=user,
            award_key=definition.key,
            defaults={'progress_snapshot': current},
        )
        if not created:
            continue

        newly_unlocked.append(award)
        if notify and getattr(user, 'notify_on_milestones', True):
            Notification.objects.create(
                user=user,
                type='milestone_unlocked',
                payload={
                    'award_key': definition.key,
                    'title': 'Milestone unlocked',
                    'message': f'You earned the {definition.title} award.',
                    'path': '/milestones',
                },
            )
    return newly_unlocked


def claim_referral(referral_token, user) -> bool:
    if not referral_token or not user or not getattr(user, 'pk', None):
        return False
    try:
        token = UUID(str(referral_token))
    except (TypeError, ValueError, AttributeError):
        return False

    with transaction.atomic():
        invite = (
            ReferralInvite.objects.select_for_update()
            .select_related('inviter')
            .filter(
                token=token,
                email__iexact=user.email,
                referred_user__isnull=True,
            )
            .first()
        )
        if not invite or invite.inviter_id == user.id:
            return False
        invite.referred_user = user
        invite.accepted_at = timezone.now()
        invite.save(update_fields=['referred_user', 'accepted_at', 'updated_at'])
        evaluate_user_awards(invite.inviter)
    return True


def awards_payload_for_user(user) -> dict:
    # Reconcile safely in case an earlier event happened before awards were deployed.
    evaluate_user_awards(user, notify=False)
    progress = award_progress_for_user(user)
    grants = {
        award.award_key: award
        for award in UserAward.objects.filter(user=user, award_key__in=AWARD_BY_KEY)
    }

    categories: list[dict] = []
    categories_by_key: dict[str, dict] = {}
    unlocked_count = 0
    for definition in AWARD_DEFINITIONS:
        grant = grants.get(definition.key)
        if grant:
            unlocked_count += 1
        category = categories_by_key.get(definition.category_key)
        if not category:
            category = {
                'key': definition.category_key,
                'title': definition.category_title,
                'awards': [],
            }
            categories_by_key[definition.category_key] = category
            categories.append(category)

        current = min(progress.get(definition.key, 0), definition.target)
        category['awards'].append(
            {
                'key': definition.key,
                'title': definition.title,
                'description': definition.description,
                'current': current,
                'target': definition.target,
                'unlocked': grant is not None,
                'unlocked_at': grant.unlocked_at if grant else None,
            }
        )

    return {
        'unlocked_count': unlocked_count,
        'total_count': len(AWARD_DEFINITIONS),
        'categories': categories,
    }
