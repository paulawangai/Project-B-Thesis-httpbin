import copy
import inspect
import random
import logging
from functools import wraps

def pure(func=None, *, ignore_params=None, allow_random=False, allow_logging=True):
    """
    Decorator to ensure a function is pure:
    - Returns the same output for the same inputs
    - Has no side effects (doesn't modify external state)
    - Doesn't rely on mutable external state
    
    Parameters:
    - ignore_params: List of parameter names to ignore when checking for modifications
    - allow_random: Whether to allow random module usage as an exception
    - allow_logging: Whether to allow logging as an exception
    
    Raises ValueError if impurity is detected.
    """
    ignore_params = ignore_params or []
    
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Create deep copies of arguments to detect modifications
            args_copy = copy.deepcopy(args)
            kwargs_copy = copy.deepcopy(kwargs)
            
            # Get parameter names to match args with their names
            param_names = list(inspect.signature(fn).parameters.keys())
            
            # Store random state if its allowed as an exception
            if allow_random:
                random_state = random.getstate()
                
            # Store original global state for comparison
            func_globals = {}
            for name in inspect.getclosurevars(fn).globals:
                if name in fn.__globals__ and name != 'random' and not (
                    allow_logging and isinstance(fn.__globals__[name], logging.Logger)):
                    try:
                        func_globals[name] = copy.deepcopy(fn.__globals__[name])
                    except (TypeError, ValueError):
                        # If can't be copied it (e.g., file objects), store its string representation
                        func_globals[name] = str(fn.__globals__[name])
            
            # Call the function
            result = fn(*args, **kwargs)
            
            # Check if positional args were modified
            for i, (original, current) in enumerate(zip(args_copy, args)):
                if i < len(param_names) and param_names[i] in ignore_params:
                    continue  # Skip ignored parameters
                
                # Skip logger parameters
                if allow_logging and isinstance(current, logging.Logger):
                    continue
                    
                try:
                    if original != current:
                        param_name = param_names[i] if i < len(param_names) else f"args[{i}]"
                        raise ValueError(f"Pure function violation in {fn.__name__}: "
                                      f"modified input positional argument '{param_name}'")
                except Exception:
                    # For objects that don't support direct comparison
                    if str(original) != str(current):
                        param_name = param_names[i] if i < len(param_names) else f"args[{i}]"
                        raise ValueError(f"Pure function violation in {fn.__name__}: "
                                      f"modified input positional argument '{param_name}'")
            
            # Check if keyword args were modified
            for key, original in kwargs_copy.items():
                if key in ignore_params:
                    continue  # Skip ignored parameters
                
                # Skip logger parameters
                if allow_logging and isinstance(kwargs[key], logging.Logger):
                    continue
                    
                current = kwargs[key]
                try:
                    if original != current:
                        raise ValueError(f"Pure function violation in {fn.__name__}: "
                                      f"modified input keyword argument '{key}'")
                except Exception:
                    # For objects that don't support direct comparison
                    if str(original) != str(current):
                        raise ValueError(f"Pure function violation in {fn.__name__}: "
                                      f"modified input keyword argument '{key}'")
            
            # Restore random state if necessary
            if allow_random:
                new_random_state = random.getstate()
                if random_state != new_random_state:
                    # The function used random, but we're allowing it
                    pass
            
            # Check if any globals were modified
            for name, original_value in func_globals.items():
                if name == 'random' and allow_random:
                    continue
                
                try:
                    current_value = fn.__globals__[name]
                    if original_value != current_value:
                        raise ValueError(f"Pure function violation in {fn.__name__}: "
                                      f"modified global variable '{name}'")
                except Exception:
                    # If comparison fails, do a deep comparison
                    if str(original_value) != str(fn.__globals__[name]):
                        raise ValueError(f"Pure function violation in {fn.__name__}: "
                                      f"modified global variable '{name}'")
            
            return result
        return wrapper
    
    # Handle both @pure and @pure() syntax
    if func is None:
        return decorator
    return decorator(func)