"""Grading model (spec §9).

``grade()`` turns findings into a 0-100 score and an A+ to F letter, per-stage sub-grades, and
the "fix these first" list. It is a pure function of the findings: re-grading the same
findings always gives the same result.
"""

from corpsec_grader.grading import (
    GRADE_MODEL_VERSION,
    WEIGHTS,
    GradeReport,
    StageGrade,
    grade,
    letter_for,
    priority,
)

__all__ = [
    "GRADE_MODEL_VERSION",
    "WEIGHTS",
    "GradeReport",
    "StageGrade",
    "grade",
    "letter_for",
    "priority",
]
