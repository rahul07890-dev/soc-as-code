"""
SOC Rule Validator Package
Automatically validates Sigma and YARA rules with synthetic test logs
"""

__version__ = "1.0.0"
__author__ = "SOC Team"

from .validate_rules import RuleValidator, LogGenerator
from .check_results import check_results

__all__ = ['RuleValidator', 'LogGenerator', 'check_results']