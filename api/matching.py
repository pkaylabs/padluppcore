from __future__ import annotations

from collections.abc import Iterable
import re


def _tokens(value) -> set[str]:
	if value is None:
		return set()
	if isinstance(value, str):
		return {item.strip().casefold() for item in value.split(',') if item.strip()}
	if isinstance(value, dict):
		items: list[str] = []
		for key, child in value.items():
			items.append(str(key))
			if isinstance(child, (str, int, float, bool)):
				items.append(str(child))
			elif isinstance(child, Iterable):
				items.extend(str(item) for item in child)
		return _tokens(','.join(items))
	if isinstance(value, Iterable):
		return {str(item).strip().casefold() for item in value if str(item).strip()}
	return set()


def _words(value: str) -> set[str]:
	return {
		word for word in re.findall(r'[a-z0-9]+', (value or '').casefold())
		if len(word) >= 3
	}


def profile_is_complete(profile) -> bool:
	"""Match the fields collected by the current onboarding flow."""

	return bool((profile.experience or '').strip() and _tokens(profile.interests))


def compatibility_details(source, candidate) -> dict:
	"""Return a stable, explainable compatibility score for two profiles."""

	if not source or not candidate:
		return {'score': 0, 'reasons': []}
	if source.pk == candidate.pk:
		return {'score': 100, 'reasons': ['This is your profile']}

	weighted_fields = [
		('Related experience', _words(source.experience), _words(candidate.experience), 20),
		('Shared interests', _tokens(source.interests), _tokens(candidate.interests), 35),
		('Shared focus areas', _tokens(source.focus_areas), _tokens(candidate.focus_areas), 15),
		('Overlapping availability', _tokens(source.availability), _tokens(candidate.availability), 10),
		('Compatible communication style', _tokens(source.communication_styles), _tokens(candidate.communication_styles), 10),
	]

	score = 0.0
	reasons: list[str] = []
	for label, source_values, candidate_values, weight in weighted_fields:
		if not source_values or not candidate_values:
			continue
		overlap = source_values & candidate_values
		if not overlap:
			continue
		score += weight * (len(overlap) / max(len(source_values), len(candidate_values)))
		preview = ', '.join(sorted(overlap)[:3])
		reasons.append(f'{label}: {preview}')

	source_tz = (source.time_zone or '').strip().casefold()
	candidate_tz = (candidate.time_zone or '').strip().casefold()
	if source_tz and candidate_tz and source_tz == candidate_tz:
		score += 10
		reasons.append('Same time zone')

	return {'score': min(100, round(score)), 'reasons': reasons[:4]}
