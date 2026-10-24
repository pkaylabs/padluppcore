from datetime import datetime, timedelta, timezone as dt_timezone
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlsplit

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.dateparse import parse_datetime
from rest_framework.test import APITestCase

from accounts.models import User
from .community_models import CommunityCategory, CommunityGroup, CommunityTask
from .models import BuddyRequest, Conversation, Goal, Match, Partnership, Profile, SubTask, Task, UserBlock


TEST_SETTINGS = {
    'BETA_WAITLIST_ONLY': False,
    'EMAIL_NOTIFICATIONS_ENABLED': False,
    'FIREBASE_PUSH_ENABLED': False,
    'PASSWORD_HASHERS': ['django.contrib.auth.hashers.MD5PasswordHasher'],
}


@override_settings(**TEST_SETTINGS)
class BuddyDirectoryTests(APITestCase):
    def setUp(self):
        self.user = self.make_user('requester', profile=True)
        self.client.force_authenticate(self.user)

    def make_user(self, slug, *, profile=False, name=None, **kwargs):
        user = User.objects.create_user(
            email=f'{slug}@directory.test', name=name or slug.title(), password='pass1234', **kwargs,
        )
        if profile:
            Profile.objects.create(user=user)
        return user

    def rows(self, response):
        self.assertEqual(response.status_code, 200, response.data)
        return response.data['results'] if isinstance(response.data, dict) else response.data

    def ids(self, response):
        return [row['user']['id'] for row in self.rows(response)]

    def test_all_other_active_users_including_incomplete_unrelated_connected_and_swiped(self):
        incomplete = self.make_user('incomplete', profile=True)
        unrelated = self.make_user('unrelated', profile=True)
        connected = self.make_user('connected', profile=True)
        liked = self.make_user('liked')
        passed = self.make_user('passed')
        Profile.objects.filter(user=self.user).update(experience='Python', interests='Django')
        Profile.objects.filter(user=unrelated).update(experience='Cooking', interests='Gardening')
        Partnership.objects.create(user_a=self.user, user_b=connected)
        Match.objects.create(from_user=self.user, to_user=liked, action=Match.LIKE)
        Match.objects.create(from_user=self.user, to_user=passed, action=Match.PASS)
        self.assertEqual(set(self.ids(self.client.get(reverse('buddies-finder')))), {
            incomplete.pk, unrelated.pk, connected.pk, liked.pk, passed.pk,
        })

    def test_excludes_self_inactive_deleted_and_both_block_directions(self):
        available = self.make_user('available')
        self.make_user('inactive', is_active=False)
        self.make_user('deleted', deleted=True)
        blocked = self.make_user('blocked')
        blocker = self.make_user('blocker')
        UserBlock.objects.create(blocker=self.user, blocked=blocked)
        UserBlock.objects.create(blocker=blocker, blocked=self.user)
        self.assertEqual(self.ids(self.client.get(reverse('buddies-finder'))), [available.pk])

    def test_missing_profiles_are_returned_without_creating_any_records_on_get(self):
        Profile.objects.filter(user=self.user).delete()
        other = self.make_user('no-profile')
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse('buddies-finder'))
        row = self.rows(response)[0]
        self.assertEqual(row['user']['id'], other.pk)
        self.assertIsNone(row['id'])
        self.assertEqual(row['bio'], '')
        self.assertEqual(row['interests'], [])
        self.assertFalse(Profile.objects.exists())
        self.assertFalse(any(query['sql'].lstrip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')) for query in queries))

    def test_latest_real_activity_controls_order_and_registration_only_fills_sorting_gaps(self):
        at = datetime(2026, 10, 20, 12, tzinfo=dt_timezone.utc)
        seen = self.make_user('recent-seen')
        login = self.make_user('recent-login')
        only_seen = self.make_user('only-seen')
        only_login = self.make_user('only-login')
        new = self.make_user('new-registration')
        old = self.make_user('old-registration')
        User.objects.filter(pk=seen.pk).update(last_seen_at=at, last_login=at - timedelta(days=5))
        User.objects.filter(pk=login.pk).update(last_seen_at=at - timedelta(days=5), last_login=at + timedelta(hours=1))
        User.objects.filter(pk=only_seen.pk).update(last_seen_at=at - timedelta(hours=1), last_login=None)
        User.objects.filter(pk=only_login.pk).update(last_seen_at=None, last_login=at - timedelta(hours=2))
        User.objects.filter(pk=new.pk).update(created_at=at + timedelta(days=1), last_seen_at=None, last_login=None)
        User.objects.filter(pk=old.pk).update(created_at=at - timedelta(days=10), last_seen_at=None, last_login=None)
        # A newer profile/registration timestamp must not override real activity.
        User.objects.filter(pk=seen.pk).update(created_at=at + timedelta(days=20))
        Profile.objects.create(user=old)
        response = self.client.get(reverse('buddies-finder'))
        self.assertEqual(self.ids(response), [new.pk, login.pk, seen.pk, only_seen.pk, only_login.pk, old.pk])
        by_id = {row['user']['id']: row for row in self.rows(response)}
        self.assertEqual(parse_datetime(by_id[seen.pk]['last_active_at']), at)
        self.assertEqual(parse_datetime(by_id[login.pk]['last_active_at']), at + timedelta(hours=1))
        self.assertEqual(parse_datetime(by_id[only_seen.pk]['last_active_at']), at - timedelta(hours=1))
        self.assertEqual(parse_datetime(by_id[only_login.pk]['last_active_at']), at - timedelta(hours=2))
        self.assertIsNone(by_id[new.pk]['last_active_at'])
        self.assertIsNone(by_id[old.pk]['last_active_at'])

    def test_activity_ties_use_stable_ascending_user_ids_even_across_pages(self):
        users = [self.make_user(f'tie-{index}') for index in range(4)]
        User.objects.filter(pk__in=[user.pk for user in users]).update(
            last_seen_at=datetime(2026, 10, 20, tzinfo=dt_timezone.utc),
        )
        ids = []
        for page in (1, 2):
            ids += self.ids(self.client.get(reverse('buddies-finder'), {'page': page, 'page_size': 2}))
        self.assertEqual(ids, [user.pk for user in users])

    def test_registration_fallback_ties_use_stable_user_ids(self):
        users = [self.make_user(f'new-tie-{index}') for index in range(3)]
        User.objects.filter(pk__in=[user.pk for user in users]).update(
            created_at=datetime(2026, 10, 20, tzinfo=dt_timezone.utc), last_seen_at=None, last_login=None,
        )
        self.assertEqual(self.ids(self.client.get(reverse('buddies-finder'))), [user.pk for user in users])

    def test_connected_incoming_outgoing_none_and_nonpending_states(self):
        connected = self.make_user('connected')
        incoming = self.make_user('incoming')
        outgoing = self.make_user('outgoing')
        none = self.make_user('none')
        rejected = self.make_user('rejected')
        accepted = self.make_user('accepted-without-partnership')
        Partnership.objects.create(user_a=self.user, user_b=connected)
        stale = BuddyRequest.objects.create(from_user=connected, to_user=self.user)
        incoming_request = BuddyRequest.objects.create(from_user=incoming, to_user=self.user)
        outgoing_request = BuddyRequest.objects.create(from_user=self.user, to_user=outgoing)
        BuddyRequest.objects.create(from_user=rejected, to_user=self.user, status=BuddyRequest.STATUS_REJECTED)
        BuddyRequest.objects.create(from_user=self.user, to_user=accepted, status=BuddyRequest.STATUS_ACCEPTED)
        rows = {row['user']['id']: row for row in self.rows(self.client.get(reverse('buddies-finder')))}
        for user, connection_status, direction, request_id in [
            (connected, 'connected', None, None),
            (incoming, 'pending', 'incoming', incoming_request.pk),
            (outgoing, 'pending', 'outgoing', outgoing_request.pk),
            (none, 'none', None, None),
            (rejected, 'none', None, None),
            (accepted, 'none', None, None),
        ]:
            with self.subTest(user=user.name):
                self.assertEqual(rows[user.pk]['connection_status'], connection_status)
                self.assertEqual(rows[user.pk]['pending_direction'], direction)
                self.assertEqual(rows[user.pk]['buddy_request_id'], request_id)
        self.assertNotEqual(rows[connected.pk]['buddy_request_id'], stale.pk)
        accepted_response = self.client.post(reverse('buddies-accept', kwargs={'pk': incoming_request.pk}))
        self.assertEqual(accepted_response.status_code, 200)
        row = next(row for row in self.rows(self.client.get(reverse('buddies-finder'))) if row['user']['id'] == incoming.pk)
        self.assertEqual(row['connection_status'], 'connected')
        self.assertIsNone(row['pending_direction'])

    def test_legacy_crossed_pending_requests_prefer_actionable_incoming(self):
        other = self.make_user('crossed')
        incoming = BuddyRequest.objects.create(from_user=other, to_user=self.user)
        BuddyRequest.objects.create(from_user=self.user, to_user=other)
        row = self.rows(self.client.get(reverse('buddies-finder')))[0]
        self.assertEqual(row['pending_direction'], 'incoming')
        self.assertEqual(row['buddy_request_id'], incoming.pk)

    def test_legacy_array_and_optional_pagination_with_default_and_capped_sizes(self):
        User.objects.bulk_create([User(email=f'page-{index}@directory.test', name=f'Page {index}') for index in range(50)])
        legacy = self.client.get(reverse('buddies-finder'), {'page_size': 1})
        self.assertIsInstance(legacy.data, list)
        self.assertEqual(len(legacy.data), 50)
        first = self.client.get(reverse('buddies-finder'), {'page': 1})
        self.assertEqual(set(first.data), {'count', 'next', 'previous', 'results'})
        self.assertEqual(first.data['count'], 50)
        self.assertEqual(len(first.data['results']), 12)
        self.assertIsNone(first.data['previous'])
        self.assertEqual(parse_qs(urlsplit(first.data['next']).query)['page'], ['2'])
        second = self.client.get(reverse('buddies-finder'), {'page': 2})
        self.assertIsNotNone(second.data['previous'])
        self.assertTrue(set(self.ids(first)).isdisjoint(self.ids(second)))
        capped = self.client.get(reverse('buddies-finder'), {'page': 1, 'page_size': 500})
        self.assertEqual(len(capped.data['results']), 48)
        last = self.client.get(reverse('buddies-finder'), {'page': 2, 'page_size': 48})
        self.assertEqual(len(last.data['results']), 2)
        self.assertIsNone(last.data['next'])

    def test_empty_directory_paginates_and_invalid_pages_are_rejected(self):
        response = self.client.get(reverse('buddies-finder'), {'page': 1})
        self.assertEqual(response.data, {'count': 0, 'next': None, 'previous': None, 'results': []})
        for page in ('-1', 'not-a-number', '2'):
            with self.subTest(page=page):
                self.assertEqual(self.client.get(reverse('buddies-finder'), {'page': page}).status_code, 404)

    def test_category_matches_candidates_goals_not_requester_profile_or_pending_requests(self):
        Profile.objects.filter(user=self.user).update(interests='Business', experience='Career')
        Goal.objects.create(user=self.user, title='My own Study goal', category='Study')
        for category in ('Career', 'Business', 'Study', 'Personal Growth'):
            candidate = self.make_user(category.replace(' ', '-'))
            Goal.objects.create(user=candidate, title='A public goal', category=category, is_public=True)
        unrelated = self.make_user('pending-business', profile=True)
        Profile.objects.filter(user=unrelated).update(interests='Study', experience='Study')
        Goal.objects.create(user=unrelated, title='Unrelated public goal', category='Business', is_public=True)
        BuddyRequest.objects.create(from_user=self.user, to_user=unrelated)
        for category in ('Career', 'Business', 'Study', 'Personal Growth'):
            with self.subTest(category=category):
                expected_ids = set(Goal.objects.filter(category=category).exclude(user=self.user).values_list('user_id', flat=True))
                response = self.client.get(reverse('buddies-finder'), {'category': category, 'page': 1})
                self.assertEqual(set(self.ids(response)), expected_ids)
                self.assertEqual(response.data['count'], len(expected_ids))

    def test_category_supports_legacy_names_trimming_and_deduplicates_multiple_goals(self):
        other = self.make_user('student')
        Goal.objects.create(user=other, title='Legacy goal', category='Education', is_public=True)
        Goal.objects.create(user=other, title='Current goal', category=' Study ', is_public=True)
        response = self.client.get(reverse('buddies-finder'), {'category': ' study ', 'page': 1})
        self.assertEqual(self.ids(response), [other.pk])
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(self.client.get(reverse('buddies-finder'), {'category': 'unknown'}).status_code, 400)

    def test_private_goal_category_does_not_affect_finder_or_search_results_or_counts(self):
        private_owner = self.make_user('private-category', name='Category Person')
        public_owner = self.make_user('public-category', name='Category Person')
        unrelated_partner = self.make_user('unrelated-partner')
        partnership = Partnership.objects.create(user_a=private_owner, user_b=unrelated_partner)
        private_goal = Goal.objects.create(
            user=private_owner, title='Private study goal', category='Study',
            is_public=False, is_shared=True, partnership=partnership,
        )
        Goal.objects.create(user=public_owner, title='Public study goal', category='Study', is_public=True)
        for endpoint in ('buddies-finder', 'buddies-search'):
            with self.subTest(endpoint=endpoint):
                params = {'query': 'Category Person', 'category': 'Study', 'page': 1}
                response = self.client.get(reverse(endpoint), params)
                self.assertEqual(self.ids(response), [public_owner.pk])
                self.assertEqual(response.data['count'], 1)
                del params['category']
                self.assertEqual(set(self.ids(self.client.get(reverse(endpoint), params))), {private_owner.pk, public_owner.pk})

        # Publishing the goal permits the category match; revoking sharing removes it.
        for is_public, expected_ids in ((True, {private_owner.pk, public_owner.pk}), (False, {public_owner.pk})):
            private_goal.is_public = is_public
            private_goal.save(update_fields=['is_public'])
            for endpoint in ('buddies-finder', 'buddies-search'):
                response = self.client.get(reverse(endpoint), {'query': 'Category Person', 'category': 'Study', 'page': 1})
                self.assertEqual(set(self.ids(response)), expected_ids)
                self.assertEqual(response.data['count'], len(expected_ids))

    def test_public_pod_enrollment_does_not_expose_goal_category(self):
        owner = self.make_user('pod-category', name='Pod Category Person')
        category, _ = CommunityCategory.objects.get_or_create(name='Study')
        group = CommunityGroup.objects.create(
            creator=owner, category=category, name='Private source group', visibility='private',
            conversation=Conversation.objects.create(is_group=True, name='Private group chat'),
        )
        pod_goal = Goal.objects.create(user=owner, title='Pod goal', category='Study', is_public=True)
        CommunityTask.objects.create(
            group=group, goal=pod_goal, creator=owner, idempotency_key='directory-category-privacy',
            visibility='public', invitation_deadline=datetime(2026, 10, 30, tzinfo=dt_timezone.utc),
        )
        for endpoint in ('buddies-finder', 'buddies-search'):
            response = self.client.get(reverse(endpoint), {'query': owner.name, 'category': 'Study', 'page': 1})
            self.assertEqual(self.ids(response), [])
            self.assertEqual(response.data['count'], 0)

    def test_finder_search_and_category_share_activity_order_and_privacy_rules(self):
        newer = self.make_user('newer', name='Test Person')
        older = self.make_user('older', name='Test Person')
        blocked = self.make_user('blocked-search', name='Test Person')
        self.make_user('inactive-search', name='Test Person', is_active=False)
        self.make_user('deleted-search', name='Test Person', deleted=True)
        UserBlock.objects.create(blocker=blocked, blocked=self.user)
        at = datetime(2026, 10, 20, tzinfo=dt_timezone.utc)
        User.objects.filter(pk=newer.pk).update(last_login=at + timedelta(days=1))
        User.objects.filter(pk=older.pk).update(last_seen_at=at)
        for other in (newer, older, blocked):
            Goal.objects.create(user=other, title='Public goal', category='Study', is_public=True)
        params = {'query': 'person', 'category': 'Study', 'page': 1, 'page_size': 1}
        finder = self.client.get(reverse('buddies-finder'), params)
        search = self.client.get(reverse('buddies-search'), params)
        self.assertEqual(self.ids(finder), [newer.pk])
        self.assertEqual(self.ids(search), [newer.pk])
        self.assertEqual(search.data['count'], 2)
        next_params = parse_qs(urlsplit(search.data['next']).query)
        self.assertEqual(next_params['query'], ['person'])
        self.assertEqual(next_params['category'], ['Study'])
        params['page'] = 2
        self.assertEqual(self.ids(self.client.get(reverse('buddies-search'), params)), [older.pk])
        legacy = self.client.get(reverse('buddies-search'), {'query': 'PERSON'})
        self.assertIsInstance(legacy.data, list)
        self.assertEqual(self.ids(legacy), [newer.pk, older.pk])

    def test_search_name_words_not_private_email_or_phone_and_never_creates_profiles(self):
        other = self.make_user('secret-address', name='Visible Name', phone='+19999999999')
        before = Profile.objects.count()
        for endpoint in ('buddies-finder', 'buddies-search'):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.ids(self.client.get(reverse(endpoint), {'query': 'Visible'})), [other.pk])
                self.assertEqual(self.ids(self.client.get(reverse(endpoint), {'query': 'secret-address'})), [])
                self.assertEqual(self.ids(self.client.get(reverse(endpoint), {'query': '+19999999999'})), [])
        self.assertEqual(Profile.objects.count(), before)
        for query in ('', '... [ ]'):
            self.assertEqual(self.client.get(reverse('buddies-search'), {'query': query}).status_code, 400)

    def test_directory_payload_only_exposes_public_user_identity(self):
        other = self.make_user('private', profile=True, phone='+18888888888')
        User.objects.filter(pk=other.pk).update(preferred_notification_email='private@secret.test', is_staff=True)
        for endpoint in ('buddies-finder', 'buddies-search'):
            response = self.client.get(reverse(endpoint), {'query': other.name})
            row = self.rows(response)[0]
            self.assertEqual(set(row['user']), {'id', 'name', 'avatar'})
            for private in ('email', 'phone', 'password', 'last_login', 'last_seen_at', 'preferred_notification_email', 'is_staff', 'is_superuser', 'is_founder'):
                self.assertNotIn(private, row)
                self.assertNotIn(private, row['user'])

    def test_buddy_profile_supports_missing_profiles_without_get_creating_rows(self):
        other = self.make_user('empty-profile')
        before = Profile.objects.count()
        response = self.client.get(reverse('buddies-profile', kwargs={'user_id': other.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['user']['id'], other.pk)
        self.assertEqual(set(response.data['user']), {'id', 'name', 'avatar'})
        self.assertIsNone(response.data['profile']['id'])
        self.assertEqual(response.data['profile']['bio'], '')
        self.assertEqual(Profile.objects.count(), before)

    def test_buddy_profile_hides_inactive_deleted_and_both_block_directions(self):
        inactive = self.make_user('inactive-profile', is_active=False)
        deleted = self.make_user('deleted-profile', deleted=True)
        blocked = self.make_user('blocked-profile')
        blocker = self.make_user('blocker-profile')
        UserBlock.objects.create(blocker=self.user, blocked=blocked)
        UserBlock.objects.create(blocker=blocker, blocked=self.user)
        for other in (inactive, deleted, blocked, blocker):
            with self.subTest(user=other.name):
                self.assertEqual(self.client.get(reverse('buddies-profile', kwargs={'user_id': other.pk})).status_code, 404)
                self.assertFalse(Profile.objects.filter(user=other).exists())

    def test_inactive_and_deleted_users_cannot_receive_connections(self):
        for other in (self.make_user('inactive-connect', is_active=False), self.make_user('deleted-connect', deleted=True)):
            response = self.client.post(reverse('buddies-connect'), {'to_user': other.pk}, format='json')
            self.assertEqual(response.status_code, 400)
            self.assertFalse(BuddyRequest.objects.filter(to_user=other).exists())

    def test_directory_requires_authentication(self):
        self.client.force_authenticate(None)
        for endpoint in ('buddies-finder', 'buddies-search'):
            self.assertEqual(self.client.get(reverse(endpoint), {'query': 'Name'}).status_code, 401)


@override_settings(**TEST_SETTINGS)
class BioOnboardingTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='bio@onboarding.test', name='Bio User', password='pass1234')
        self.profile = Profile.objects.create(
            user=self.user, bio='Existing bio', experience='Engineer', interests='Study,Business',
            location='Lagos', focus_areas=['Writing'], availability={'evening': True},
        )
        self.client.force_authenticate(self.user)

    def test_initial_registration_still_does_not_require_bio(self):
        self.client.force_authenticate(None)
        response = self.client.post(reverse('onboarding-register'), {
            'name': 'New Person', 'email': 'new@onboarding.test', 'password': 'pass1234',
        }, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertIn('token', response.data)
        self.assertEqual(Profile.objects.get(user_id=response.data['user']['id']).bio, '')

    def test_legacy_bioless_users_can_still_login(self):
        self.profile.bio = ''
        self.profile.save(update_fields=['bio'])
        self.client.force_authenticate(None)
        response = self.client.post(reverse('auth-login'), {'email': self.user.email, 'password': 'pass1234'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.data)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {response.data['token']}")
        self.assertEqual(self.client.get(reverse('auth-userprofile')).data['bio'], '')

    def test_profile_patch_rejects_explicit_blank_whitespace_or_null_bio(self):
        for bio in ('', ' \r\n\t ', None):
            with self.subTest(bio=bio):
                response = self.client.patch(reverse('onboarding-profile'), {'bio': bio, 'location': 'Should not persist'}, format='json')
                self.assertEqual(response.status_code, 400)
                self.assertIn('bio', response.data)
                self.profile.refresh_from_db()
                self.assertEqual(self.profile.bio, 'Existing bio')
                self.assertEqual(self.profile.location, 'Lagos')

    def test_profile_patch_trims_bio_and_does_not_wipe_unrelated_fields(self):
        response = self.client.patch(reverse('onboarding-profile'), {'bio': '  New bio\n '}, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['bio'], 'New bio')
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.experience, 'Engineer')
        self.assertEqual(self.profile.interests, 'Study,Business')
        self.assertEqual(self.profile.location, 'Lagos')

    def test_profile_partial_updates_without_bio_keep_working_for_legacy_users(self):
        self.profile.bio = ''
        self.profile.save(update_fields=['bio'])
        response = self.client.patch(reverse('onboarding-profile'), {'location': 'Abuja'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['bio'], '')
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.location, 'Abuja')

    def test_set_experience_accepts_optional_bio_only_and_preserves_other_profile_fields(self):
        response = self.client.post(reverse('onboarding-set-experience'), {'bio': '  About me  '}, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['bio'], 'About me')
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.experience, 'Engineer')
        self.assertEqual(self.profile.interests, 'Study,Business')
        self.assertEqual(self.profile.focus_areas, ['Writing'])
        self.assertEqual(self.profile.availability, {'evening': True})
        self.assertEqual(self.profile.location, 'Lagos')

    def test_set_and_update_experience_reject_invalid_bio_atomically(self):
        for method, endpoint in (('post', 'onboarding-set-experience'), ('patch', 'onboarding-update-experience')):
            for bio in ('', '\n \t', None):
                with self.subTest(endpoint=endpoint, bio=bio):
                    response = getattr(self.client, method)(reverse(endpoint), {'bio': bio, 'experience': 'Not saved'}, format='json')
                    self.assertEqual(response.status_code, 400)
                    self.assertIn('bio', response.data)
                    self.profile.refresh_from_db()
                    self.assertEqual(self.profile.bio, 'Existing bio')
                    self.assertEqual(self.profile.experience, 'Engineer')

    def test_set_experience_preserves_unsupplied_bio_and_accepts_legacy_interest_formats(self):
        for interests in (['  Career  ', 'Study'], 'Career,Study'):
            response = self.client.post(reverse('onboarding-set-experience'), {'interests': interests}, format='json')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data['interests'], ['Career', 'Study'])
            self.assertEqual(response.data['bio'], 'Existing bio')
            self.assertEqual(response.data['experience'], 'Engineer')

    def test_null_legacy_experience_or_interests_does_not_clear_data(self):
        response = self.client.post(reverse('onboarding-set-experience'), {'experience': None, 'interests': None, 'bio': 'Updated'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.experience, 'Engineer')
        self.assertEqual(self.profile.interests, 'Study,Business')

    def test_update_experience_accepts_bio_without_experience_or_interests(self):
        response = self.client.patch(reverse('onboarding-update-experience'), {'bio': '\nUpdated bio  '}, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['bio'], 'Updated bio')
        self.assertEqual(self.client.patch(reverse('onboarding-update-experience'), {}, format='json').status_code, 400)

    def test_complete_requires_existing_nonblank_bio_and_cannot_be_bypassed_with_request_fields(self):
        for bio in ('', ' \n\t'):
            self.profile.bio = bio
            self.profile.save(update_fields=['bio'])
            response = self.client.post(reverse('onboarding-complete'), {'bio': 'Unsaved request bio', 'completed': True}, format='json')
            self.assertEqual(response.status_code, 400)
            self.assertIn('bio', response.data)
            self.profile.refresh_from_db()
            self.assertEqual(self.profile.bio, bio)

    def test_complete_with_no_profile_fails_without_creating_a_profile(self):
        self.profile.delete()
        response = self.client.post(reverse('onboarding-complete'), {}, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('bio', response.data)
        self.assertFalse(Profile.objects.filter(user=self.user).exists())

    def test_complete_without_image_returns_existing_user_profile_contract(self):
        response = self.client.post(reverse('onboarding-complete'), {}, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.data), {'user', 'profile'})
        self.assertEqual(response.data['user']['id'], self.user.pk)
        self.assertEqual(response.data['user']['email'], self.user.email)
        self.assertIsNone(response.data['user']['avatar'])
        self.assertEqual(response.data['profile']['bio'], 'Existing bio')
        # The saved profile, not another user's or an arbitrary posted object, is validated.
        self.assertEqual(response.data['profile']['id'], self.profile.pk)
        self.assertEqual(self.client.post(reverse('onboarding-complete')).status_code, 200)

    def test_avatar_edits_remain_allowed_but_do_not_bypass_completion_bio_validation(self):
        self.profile.bio = ''
        self.profile.save(update_fields=['bio'])
        with TemporaryDirectory() as media_root, override_settings(MEDIA_ROOT=media_root):
            avatar = SimpleUploadedFile('avatar.gif', b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;', content_type='image/gif')
            response = self.client.patch(reverse('onboarding-user-avatar'), {'avatar': avatar}, format='multipart')
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.data['avatar'])
            self.assertEqual(self.client.post(reverse('onboarding-complete')).status_code, 400)

    def test_completion_is_authenticated_post_only(self):
        self.assertEqual(self.client.get(reverse('onboarding-complete')).status_code, 405)
        self.client.force_authenticate(None)
        self.assertEqual(self.client.post(reverse('onboarding-complete')).status_code, 401)


@override_settings(**TEST_SETTINGS)
class WorkItemDatetimeTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email='owner@datetime.test', name='Owner', password='pass1234')
        self.partner = User.objects.create_user(email='partner@datetime.test', name='Partner', password='pass1234')
        self.stranger = User.objects.create_user(email='stranger@datetime.test', name='Stranger', password='pass1234')
        self.partnership = Partnership.objects.create(user_a=self.owner, user_b=self.partner)
        self.goal = Goal.objects.create(user=self.owner, partnership=self.partnership, title='Shared goal')
        self.task = Task.objects.create(goal=self.goal, owner=self.owner, title='Task', description='Keep description')
        self.subtask = SubTask.objects.create(task=self.task, owner=self.owner, title='Subtask')
        self.client.force_authenticate(self.owner)

    def test_task_patch_due_at_with_timezone_preserves_title_owner_and_other_fields(self):
        response = self.client.patch(reverse('tasks-detail', kwargs={'pk': self.task.pk}), {
            'due_at': '2026-10-25T18:45:00+01:00',
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.task.refresh_from_db()
        self.assertEqual(self.task.due_at, datetime(2026, 10, 25, 17, 45, tzinfo=dt_timezone.utc))
        self.assertEqual(self.task.title, 'Task')
        self.assertEqual(self.task.description, 'Keep description')
        self.assertEqual(self.task.owner_id, self.owner.pk)

    def test_task_due_at_can_be_cleared_or_omitted(self):
        self.task.due_at = datetime(2026, 10, 25, 17, 45, tzinfo=dt_timezone.utc)
        self.task.save(update_fields=['due_at'])
        url = reverse('tasks-detail', kwargs={'pk': self.task.pk})
        self.assertEqual(self.client.patch(url, {'title': 'Renamed'}, format='json').status_code, 200)
        self.task.refresh_from_db()
        self.assertIsNotNone(self.task.due_at)
        response = self.client.patch(url, {'due_at': None}, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data['due_at'])
        self.task.refresh_from_db()
        self.assertIsNone(self.task.due_at)

    def test_task_due_at_rejects_invalid_datetime_without_saving_other_edits(self):
        response = self.client.patch(reverse('tasks-detail', kwargs={'pk': self.task.pk}), {
            'due_at': 'not-a-date', 'title': 'Not saved',
        }, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('due_at', response.data)
        self.task.refresh_from_db()
        self.assertIsNone(self.task.due_at)
        self.assertEqual(self.task.title, 'Task')

    def test_partner_and_stranger_cannot_patch_task_datetime_or_forge_ownership(self):
        url = reverse('tasks-detail', kwargs={'pk': self.task.pk})
        for user, expected in ((self.partner, 403), (self.stranger, 404)):
            self.client.force_authenticate(user)
            response = self.client.patch(url, {'due_at': '2026-10-25T18:00:00Z', 'owner': user.pk}, format='json')
            self.assertEqual(response.status_code, expected)
        self.task.refresh_from_db()
        self.assertIsNone(self.task.due_at)
        self.assertEqual(self.task.owner_id, self.owner.pk)

    def test_subtask_datetime_is_writable_and_nullable(self):
        url = reverse('subtasks-detail', kwargs={'pk': self.subtask.pk})
        response = self.client.patch(url, {'due_at': '2026-10-25T19:30:00-04:00'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.subtask.refresh_from_db()
        self.assertEqual(self.subtask.due_at, datetime(2026, 10, 25, 23, 30, tzinfo=dt_timezone.utc))
        response = self.client.patch(url, {'due_at': None}, format='json')
        self.assertEqual(response.status_code, 200)
        self.subtask.refresh_from_db()
        self.assertIsNone(self.subtask.due_at)

    def test_nonowners_cannot_change_subtask_due_at(self):
        for user in (self.partner, self.stranger):
            self.client.force_authenticate(user)
            response = self.client.patch(reverse('subtasks-detail', kwargs={'pk': self.subtask.pk}), {
                'due_at': '2026-10-25T18:00:00Z',
            }, format='json')
            self.assertEqual(response.status_code, 404)
        self.subtask.refresh_from_db()
        self.assertIsNone(self.subtask.due_at)

    def test_subtask_update_cannot_be_reassigned_to_someone_elses_task(self):
        foreign_task = Task.objects.create(goal=self.goal, owner=self.partner, title='Partner task')
        response = self.client.patch(reverse('subtasks-detail', kwargs={'pk': self.subtask.pk}), {
            'task': foreign_task.pk, 'due_at': '2026-10-25T18:00:00Z',
        }, format='json')
        self.assertEqual(response.status_code, 403)
        self.subtask.refresh_from_db()
        self.assertEqual(self.subtask.task_id, self.task.pk)
        self.assertIsNone(self.subtask.due_at)
