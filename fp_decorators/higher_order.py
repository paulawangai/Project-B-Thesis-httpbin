"""
Higher-order function module.

This module provides decorators for working with higher-order functions:
- Functions that take other functions as arguments
- Functions that return other functions
- Common higher-order function patterns like compose, pipe, curry, and partial application

Parameters:
- compose: Combines functions right-to-left (f(g(h(x))))
- pipe: Combines functions left-to-right (h(g(f(x))))
- curry: Enables partial function application by argument
- partial: Creates specialized versions of functions with fixed arguments
- memoize: Caches function results for repeated calls with same arguments

Raises TypeError if pipeline functions receive incorrect arguments.
"""
import functools
import inspect
from typing import Callable, Any, TypeVar, List, Dict, Optional, Union, Tuple

# Type variables for type hinting
F = TypeVar('F', bound=Callable)
T = TypeVar('T')
R = TypeVar('R')

def compose(*funcs):
    """
    Compose multiple functions together, executing from right to left.
    
    Example:
        compose(f, g, h)(x) is equivalent to f(g(h(x)))
    
    Args:
        *funcs: Functions to compose
        
    Returns:
        A function representing the composition of the input functions
    """
    if not funcs:
        return lambda x: x
    
    def composed_function(x):
        result = x
        for f in reversed(funcs):
            result = f(result)
        return result
        
    return composed_function


def pipe(*funcs):
    """
    Pipe data through a series of functions, executing from left to right.
    
    Example:
        pipe(f, g, h)(x) is equivalent to h(g(f(x)))
    
    Args:
        *funcs: Functions to pipe through
        
    Returns:
        A function representing the piping of the input functions
    """
    if not funcs:
        return lambda x: x
    
    def piped_function(x):
        result = x
        for f in funcs:
            result = f(result)
        return result
        
    return piped_function


def curry(func=None, *, arity=None):
    """
    Curries a function, allowing partial application of arguments.
    
    Example:
        @curry
        def add(a, b, c):
            return a + b + c
            
        add(1)(2)(3)  # Returns 6
        add(1, 2)(3)  # Also returns 6
        add(1)(2, 3)  # Also returns 6
    
    Args:
        func: The function to curry
        arity: Optional fixed arity for the function (useful for variadic functions)
        
    Returns:
        A curried version of the function
    """
    def _curry(fn):
        if arity is None:
            # Get the number of required arguments
            sig = inspect.signature(fn)
            required_args = sum(1 for param in sig.parameters.values() 
                                if param.default is param.empty and 
                                   param.kind not in (param.VAR_POSITIONAL, param.VAR_KEYWORD))
            fn_arity = required_args
        else:
            fn_arity = arity
        
        @functools.wraps(fn)
        def curried(*args, **kwargs):
            if len(args) + len(kwargs) >= fn_arity:
                return fn(*args, **kwargs)
            
            @functools.wraps(fn)
            def inner(*more_args, **more_kwargs):
                combined_args = args + more_args
                combined_kwargs = {**kwargs, **more_kwargs}
                return curried(*combined_args, **combined_kwargs)
            
            return inner
        
        return curried
    
    if func is None:
        return _curry
    return _curry(func)


def partial(func, *args, **kwargs):
    """
    Creates a partial application of a function with some arguments fixed.
    
    !!Unlike functools.partial, this returns a function that's easier to use
    with other higher-order functions and respects type hints better.
    
    Example:
        add_5 = partial(add, 5)
        add_5(10)  # Returns 15
    
    Args:
        func: The function to partially apply
        *args: Positional arguments to fix
        **kwargs: Keyword arguments to fix
        
    Returns:
        A partially applied function
    """
    @functools.wraps(func)
    def partially_applied(*more_args, **more_kwargs):
        return func(*args, *more_args, **{**kwargs, **more_kwargs})
    
    return partially_applied


def memoize(func=None, *, max_size=None, key_func=None):
    """
    Memoizes a function, caching its results for repeated calls with the same args.
    
    Args:
        func: The function to memoize
        max_size: Optional maximum cache size (LRU eviction if exceeded)
        key_func: Optional function to calculate cache key (default: args and kwargs)
        
    Returns:
        A memoized version of the function
    """
    def _memoize(fn):
        cache = {}
        
        if max_size is not None:
            # Simple LRU implementation
            order = []
        
        @functools.wraps(fn)
        def memoized(*args, **kwargs):
            # Create a cache key
            if key_func is not None:
                key = key_func(*args, **kwargs)
            else:
                # Default key is based on the arguments
                key = (args, frozenset(kwargs.items())) if kwargs else args
            
            # Try to find the result in cache
            if key in cache:
                # Update LRU order if needed
                if max_size is not None:
                    order.remove(key)
                    order.append(key)
                return cache[key]
            
            # Call the function and cache result
            result = fn(*args, **kwargs)
            cache[key] = result
            
            # Handle max_size for LRU cache
            if max_size is not None:
                order.append(key)
                if len(order) > max_size:
                    oldest_key = order.pop(0)
                    del cache[oldest_key]
                    
            return result
        
        # Add a method to clear the cache
        memoized.clear_cache = lambda: cache.clear()
        
        return memoized
    
    if func is None:
        return _memoize
    return _memoize(func)


def map_reduce(mapper: Callable[[T], R], reducer: Callable[[R, R], R], initial_value: Optional[R] = None):
    """
    Creates a map-reduce function that applies mapper to each item and reduces the results.
    
    Example:
        sum_squares = map_reduce(lambda x: x**2, lambda acc, x: acc + x, 0)
        sum_squares([1, 2, 3, 4])  # Returns 30 (1² + 2² + 3² + 4²)
    
    Args:
        mapper: Function to apply to each element
        reducer: Function to combine results
        initial_value: Initial value for the reduction
        
    Returns:
        A function that applies the map-reduce operation to a collection
    """
    def map_reduce_fn(collection):
        # Apply mapper to each element
        mapped = [mapper(item) for item in collection]
        
        # Handle empty collections
        if not mapped:
            return initial_value
        
        # Use initial_value if provided, otherwise use first element
        if initial_value is not None:
            result = initial_value
            start_idx = 0
        else:
            result = mapped[0]
            start_idx = 1
        
        # Apply reducer to combine results
        for i in range(start_idx, len(mapped)):
            result = reducer(result, mapped[i])
            
        return result
    
    return map_reduce_fn


def trampoline(func):
    """
    Implements trampolining to avoid stack overflow in recursive functions.
    
    The decorated function should return either a value or a thunk (a function
    with zero arguments) that returns the next computational step.
    
    Example:
        @trampoline
        def factorial(n, acc=1):
            if n <= 1:
                return acc
            # Return a thunk (function with no args) for the next step
            return lambda: factorial(n-1, n*acc)
    
    Args:
        func: The function to apply trampolining to
        
    Returns:
        A trampolined version of the function
    """
    @functools.wraps(func)
    def trampolined(*args, **kwargs):
        result = func(*args, **kwargs)
        
        # Keep calling the returned function as long as it's callable
        while callable(result) and not isinstance(result, type):
            result = result()
            
        return result
    
    return trampolined


# Higher-order decorator
def higher_order(func=None, *, enhanced=False):
    """
    Marks a function as a higher-order function and enhances it with additional capabilities.
    
    When enhanced=True, the function gains additional methods:
    - compose: Compose with other functions (right to left)
    - pipe: Pipe through other functions (left to right)
    - curry: Return a curried version of the function
    - partial: Return a partially applied version of the function
    
    Example:
        @higher_order(enhanced=True)
        def add(a, b):
            return a + b
            
        # Now we can do:
        add.curry()(1)(2)  # Returns 3
        add.partial(1)(2)  # Returns 3
        
        # And compose with other functions:
        multiply_by_2 = lambda x: x * 2
        add_and_double = add.compose(multiply_by_2)  # multiply_by_2 ∘ add
    
    Args:
        func: The function to mark as higher-order
        enhanced: Whether to add enhancement methods
        
    Returns:
        The function, possibly enhanced with additional higher-order capabilities
    """
    def _higher_order(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        
        # Mark as a higher-order function
        wrapper._is_higher_order = True
        
        if enhanced:
            # Add enhancement methods
            wrapper.compose = lambda *funcs: compose(*(list(funcs) + [wrapper]))
            wrapper.pipe = lambda *funcs: pipe(*([wrapper] + list(funcs)))
            wrapper.curry = lambda: curry(wrapper)
            wrapper.partial = lambda *args, **kwargs: partial(wrapper, *args, **kwargs)
            wrapper.memoized = lambda **kwargs: memoize(wrapper, **kwargs)
            
        return wrapper
    
    if func is None:
        return _higher_order
    return _higher_order(func)


def is_higher_order(func):
    """
    Check if a function is a higher-order function.
    
    Args:
        func: The function to check
        
    Returns:
        True if the function is higher-order, False otherwise
    """
    # Check for the marker attribute
    if hasattr(func, '_is_higher_order'):
        return func._is_higher_order
    
    # Check if it's already a known higher-order function from this module
    if func in [compose, pipe, curry, partial, memoize, map_reduce, trampoline, higher_order, is_higher_order]:
        return True
    
    # Inspect the function signature and implementation
    try:
        sig = inspect.signature(func)
        
        # Check if any parameter is callable
        has_callable_param = any(
            param.annotation == Callable or 
            getattr(param.annotation, '__origin__', None) == Callable
            for param in sig.parameters.values()
        )
        
        # Check if return type is callable
        return_is_callable = (
            sig.return_annotation == Callable or
            getattr(sig.return_annotation, '__origin__', None) == Callable
        )
        
        # check if the function name says it's higher-order
        name_suggests_ho = any(term in func.__name__.lower() 
                              for term in ['map', 'filter', 'reduce', 'compose', 'apply', 'partial'])
        
        return has_callable_param or return_is_callable or name_suggests_ho
    except (ValueError, TypeError):
        # If function can't be inspected, assume it's not higher-order
        return False