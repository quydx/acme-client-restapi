FAILE_CODE = 'failed'
SUCCESS_CODE = 'success'
VALID_CODE = 'valid'
INVALID_CODE = 'invalid'

LIMIT_RATE_ERROR = {
    "status" : FAILE_CODE,
    "cause": "domain is in limit rate"
}


EMAIL_NOT_ORDER = {
    "status" : FAILE_CODE,
    "cause": "this email is not found in orders"
}

DOMAIN_NOT_ORDER = {
    "status" : FAILE_CODE,
    "cause": "this email is not found in orders"
}


FORBIDDEN_CODE = {
    "status": "forbidden",
    "cause": "missing parameters or wrong method"
}


CHALLENGE_ERROR = {
    "status" : FAILE_CODE,
    "cause": "challenge for this domain is not complete"
}