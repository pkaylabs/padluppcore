#!/usr/bin/env python3
"""Compare two Django JSON fixtures without depending on record order."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


ZERO_FRACTION_UTC = re.compile(
    r'^(?P<seconds>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.0+Z$'
)


def load_fixture(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise ValueError(f'{path} is not a Django JSON fixture')
    return data


def normalize_database_value(value):
    if isinstance(value, dict):
        return {key: normalize_database_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_database_value(item) for item in value]
    if isinstance(value, str):
        timestamp_match = ZERO_FRACTION_UTC.fullmatch(value)
        if timestamp_match:
            return f'{timestamp_match.group("seconds")}Z'
    return value


def canonical_record(record: dict) -> str:
    return json.dumps(
        normalize_database_value(record),
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True,
    )


def model_counts(records: list[dict]) -> Counter:
    return Counter(str(record.get('model', '')) for record in records)


def records_by_model(records: list[dict]) -> dict[str, Counter]:
    grouped: dict[str, Counter] = {}
    for record in records:
        model = str(record.get('model', ''))
        grouped.setdefault(model, Counter())[canonical_record(record)] += 1
    return grouped


def changed_field_counts(source: list[dict], target: list[dict]) -> Counter:
    def index(records: list[dict]) -> dict[tuple[str, str], dict | None]:
        indexed: dict[tuple[str, str], dict | None] = {}
        for record in records:
            identity = (
                str(record.get('model', '')),
                json.dumps(record.get('pk'), sort_keys=True, ensure_ascii=True),
            )
            indexed[identity] = record if identity not in indexed else None
        return indexed

    source_index = index(source)
    target_index = index(target)
    changed = Counter()
    for identity in source_index.keys() & target_index.keys():
        source_record = source_index[identity]
        target_record = target_index[identity]
        if source_record is None or target_record is None:
            continue
        source_fields = source_record.get('fields', {})
        target_fields = target_record.get('fields', {})
        for field in source_fields.keys() | target_fields.keys():
            if source_fields.get(field) != target_fields.get(field):
                changed[(identity[0], str(field))] += 1
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('target', type=Path)
    args = parser.parse_args()

    source = load_fixture(args.source)
    target = load_fixture(args.target)
    source_records = Counter(canonical_record(record) for record in source)
    target_records = Counter(canonical_record(record) for record in target)

    if source_records != target_records:
        source_counts = model_counts(source)
        target_counts = model_counts(target)
        source_by_model = records_by_model(source)
        target_by_model = records_by_model(target)
        print('Fixture comparison failed.')
        for model in sorted(source_counts.keys() | target_counts.keys()):
            source_model_records = source_by_model.get(model, Counter())
            target_model_records = target_by_model.get(model, Counter())
            if source_model_records != target_model_records:
                missing = sum((source_model_records - target_model_records).values())
                unexpected = sum((target_model_records - source_model_records).values())
                print(
                    f'{model}: source={source_counts[model]} target={target_counts[model]} '
                    f'missing={missing} unexpected={unexpected}'
                )
        print(f'Missing records: {sum((source_records - target_records).values())}')
        print(f'Unexpected records: {sum((target_records - source_records).values())}')
        changed_fields = changed_field_counts(source, target)
        if changed_fields:
            print('Changed fields by model:')
            for (model, field), count in sorted(changed_fields.items()):
                print(f'{model}.{field}: {count}')
        return 1

    print(
        f'Fixtures match: {len(source)} records across '
        f'{len(model_counts(source))} models (database-normalized values).'
    )
    for model, count in sorted(model_counts(source).items()):
        print(f'{model}: {count}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
