from enum import Enum

class StatusEnum(str, Enum):
    PENDING = 'pending'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    ON_HOLD = 'on_hold'