import copy
import inspect
from functools import wraps

def immutable(func=None, *, deep_copy=True, freeze_input=False):
    """
    Decorator to enforce immutability in a function:
    - Creates deep copies of mutable input arguments (lists, dicts, etc.)
    - Verifies original inputs aren't modified
    - Optionally "freezes" inputs by converting to immutable types
    
    Parameters:
    - deep_copy: Whether to use deep copying for inputs (default: True)
    - freeze_input: Whether to convert inputs to immutable versions (default: False)
                   e.g. lists to tuples, dicts to frozendict, etc.
    
    Raises ValueError if immutability is violated.
    """
    def to_immutable(obj):
        """Convert mutable objects to immutable versions"""
        if isinstance(obj, list):
            return tuple(to_immutable(item) for item in obj)
        elif isinstance(obj, dict):
            return frozenset((k, to_immutable(v)) for k, v in obj.items())
        elif isinstance(obj, set):
            return frozenset(to_immutable(item) for item in obj)
        else:
            return obj
            
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Deep copy arguments if they're mutable
            if deep_copy:
                copied_args = tuple(copy.deepcopy(arg) for arg in args)
                copied_kwargs = {key: copy.deepcopy(value) for key, value in kwargs.items()}
            else:
                copied_args = args
                copied_kwargs = kwargs
            
            # If freeze_input is True, convert mutable arguments to immutable versions
            if freeze_input:
                immutable_args = tuple(to_immutable(arg) for arg in copied_args)
                immutable_kwargs = {key: to_immutable(value) for key, value in copied_kwargs.items()}
                result = fn(*immutable_args, **immutable_kwargs)
            else:
                # Original args before function call (for comparison later)
                args_before = copy.deepcopy(copied_args)
                kwargs_before = copy.deepcopy(copied_kwargs)
                
                # Call the function with copied arguments
                result = fn(*copied_args, **copied_kwargs)
                
                # Verify input arguments weren't modified
                args_after = copied_args
                kwargs_after = copied_kwargs
                
                # Check if positional args were modified
                for i, (before, after) in enumerate(zip(args_before, args_after)):
                    try:
                        if before != after:
                            param_names = list(inspect.signature(fn).parameters.keys())
                            param_name = param_names[i] if i < len(param_names) else f"args[{i}]"
                            raise ValueError(f"Immutability violation in {fn.__name__}: "
                                          f"modified input positional argument '{param_name}'")
                    except Exception as e:
                        # For objects that don't support direct comparison
                        if str(before) != str(after):
                            param_names = list(inspect.signature(fn).parameters.keys())
                            param_name = param_names[i] if i < len(param_names) else f"args[{i}]"
                            raise ValueError(f"Immutability violation in {fn.__name__}: "
                                          f"modified input positional argument '{param_name}'")
                
                # Check if keyword args were modified
                for key, before in kwargs_before.items():
                    after = kwargs_after[key]
                    try:
                        if before != after:
                            raise ValueError(f"Immutability violation in {fn.__name__}: "
                                          f"modified input keyword argument '{key}'")
                    except Exception:
                        # For objects that don't support direct comparison
                        if str(before) != str(after):
                            raise ValueError(f"Immutability violation in {fn.__name__}: "
                                          f"modified input keyword argument '{key}'")
            
            return result
        
        return wrapper
    
    # Handle both @immutable and @immutable() syntax
    if func is None:
        return decorator
    return decorator(func)