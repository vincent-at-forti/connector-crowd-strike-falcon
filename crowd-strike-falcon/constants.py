"""
  Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end
"""
PARAM_MAPPING = {
    "Date Updated": "date_updated|desc",
    "Last Behaviour Descending": "last_behavior|desc",
    "Last Behaviour Ascending": "last_behavior|asc",
    "Last Hour": ">'now-1h'",
    "Last Day": ">'now-1d'",
    "Last Week": ">'now-7d'",
    "Last 30 days": ">'now-30d'",
    "Last 90 days": ">'now-90d'",
    "Date Histogram": "date_histogram",
    "Date Range": "date_range",
    "Terms": "terms",
    "Range": "range",
    "Cardinality": "cardinality",
    "Max": "max",
    "Min": "min",
    "Year": "year",
    "Month": "month",
    "Week": "week",
    "Day": "day",
    "Hour": "hour",
    "Minute": "minute",
    "IPv4": "ipv4",
    "IPv6": "ipv6",
    "Domain": "domain",
    "MD5": "md5",
    "SHA256": "sha256",
    "SHA1": "sha1"
}

STATUS_MAPPING = {
    "New": "new",
    "In Progress": "in_progress",
    "True Positive": "true_positive",
    "False Positive": "false_positive",
    "Ignored": "ignored",
    "Closed": "closed",
    "Reopened": "reopened"
}

STATUS_NUM_MAPPING = {
    "New": "20",
    "Reopened": "25",
    "In Progress": "30",
    "Closed": "40"
}
