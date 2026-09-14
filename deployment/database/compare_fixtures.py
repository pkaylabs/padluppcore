#!/usr/bin/env python3
"""Compare two Django JSON fixtures without depending on record order."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def load_fixture(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise ValueError(f'{path} is not a Django JSON fixture')
    return data


def canonical_record(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def model_counts(records: list[dict]) -> Counter:
    return Counter(str(record.get('model', '')) for record in records)


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
        print('Fixture comparison failed.')
        for model in sorted(source_counts.keys() | target_counts.keys()):
            if source_counts[model] != target_counts[model]:
                print(f'{model}: source={source_counts[model]} target={target_counts[model]}')
        print(f'Missing records: {sum((source_records - target_records).values())}')
        print(f'Unexpected records: {sum((target_records - source_records).values())}')
        return 1

    print(f'Fixtures match exactly: {len(source)} records across {len(model_counts(source))} models.')
    for model, count in sorted(model_counts(source).items()):
        print(f'{model}: {count}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
