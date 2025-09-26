from typing import Any, Dict

def mask_sensitive_values(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively mask sensitive values in dictionaries."""
    masked = {}
    sensitive_keys = {
        'password', 'secret', 'key', 'token', 
        'api_key', 'apikey', 'auth', 'credential'
    }
    
    for k, v in data.items():
        if isinstance(v, dict):
            masked[k] = mask_sensitive_values(v)
        elif isinstance(v, str) and any(sens in k.lower() for sens in sensitive_keys):
            if len(v) > 6:
                masked[k] = f"{v[:2]}{'*' * (len(v)-4)}{v[-2:]}"
            else:
                masked[k] = '*' * len(v)
        else:
            masked[k] = v
    return masked