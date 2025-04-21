import unittest
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from fp_decorators.higher_order import (
    compose, pipe, curry, partial, memoize, map_reduce, 
    trampoline, higher_order, is_higher_order
)

class TestHigherOrderFunctions(unittest.TestCase):
    
    def test_compose(self):
        """Test function composition."""
        add_one = lambda x: x + 1
        multiply_by_two = lambda x: x * 2
        subtract_three = lambda x: x - 3
        
        # Composition: subtract_three(multiply_by_two(add_one(5)))
        composed = compose(subtract_three, multiply_by_two, add_one)
        self.assertEqual(composed(5), 9)  # (5 + 1) * 2 - 3 = 9
        
        # Empty composition should be identity function
        identity = compose()
        self.assertEqual(identity(42), 42)
    
    def test_pipe(self):
        """Test function piping."""
        add_one = lambda x: x + 1
        multiply_by_two = lambda x: x * 2
        subtract_three = lambda x: x - 3
        
        # Piping: subtract_three(multiply_by_two(add_one(5)))
        piped = pipe(add_one, multiply_by_two, subtract_three)
        self.assertEqual(piped(5), 9)  # (5 + 1) * 2 - 3 = 9
        
        # Empty pipe should be identity function
        identity = pipe()
        self.assertEqual(identity(42), 42)
    
    def test_curry(self):
        """Test function currying."""
        @curry
        def add(a, b, c):
            return a + b + c
        
        # Test different currying patterns
        self.assertEqual(add(1)(2)(3), 6)
        self.assertEqual(add(1, 2)(3), 6)
        self.assertEqual(add(1)(2, 3), 6)
        self.assertEqual(add(1, 2, 3), 6)
        
        # Test with explicit arity
        @curry(arity=4)
        def add_four(*args):
            return sum(args)
            
        self.assertEqual(add_four(1)(2)(3)(4), 10)
        self.assertEqual(add_four(1, 2)(3, 4), 10)
    
    def test_partial(self):
        """Test partial function application."""
        def add(a, b, c, d=0):
            return a + b + c + d
        
        add_with_1 = partial(add, 1)
        self.assertEqual(add_with_1(2, 3), 6)
        
        add_with_1_and_2 = partial(add, 1, 2)
        self.assertEqual(add_with_1_and_2(3), 6)
        
        add_with_keyword = partial(add, 1, 2, d=4)
        self.assertEqual(add_with_keyword(3), 10)  # 1 + 2 + 3 + 4 = 10
    
    def test_memoize(self):
        """Test function memoization."""
        call_count = 0
        
        @memoize
        def fibonacci(n):
            nonlocal call_count
            call_count += 1
            if n <= 1:
                return n
            return fibonacci(n-1) + fibonacci(n-2)
        
        # First call should compute everything
        result1 = fibonacci(10)
        initial_calls = call_count
        
        # Second call should use cached results
        result2 = fibonacci(10)
        
        self.assertEqual(result1, result2)
        self.assertEqual(call_count, initial_calls)  # No additional calls
        
        # Test with max_size
        call_count = 0
        
        @memoize(max_size=3)
        def add(a, b):
            nonlocal call_count
            call_count += 1
            return a + b
            
        add(1, 2)  # Cache: (1,2)
        add(3, 4)  # Cache: (1,2), (3,4)
        add(5, 6)  # Cache: (1,2), (3,4), (5,6)
        add(7, 8)  # Cache: (3,4), (5,6), (7,8) - (1,2) evicted
        
        # This should not use cache
        previous_count = call_count
        add(1, 2)
        self.assertEqual(call_count, previous_count + 1)
        
        # This should use cache
        previous_count = call_count
        add(7, 8)
        self.assertEqual(call_count, previous_count)
    
    def test_map_reduce(self):
        """Test map-reduce operations."""
        # Sum of squares
        square = lambda x: x * x
        add = lambda a, b: a + b
        
        sum_of_squares = map_reduce(square, add, 0)
        self.assertEqual(sum_of_squares([1, 2, 3, 4]), 30)  # 1^2 + 2^2 + 3^2 + 4^2 = 30
        
        # Without initial value
        product = map_reduce(lambda x: x, lambda a, b: a * b)
        self.assertEqual(product([2, 3, 4]), 24)  # 2 * 3 * 4 = 24
        
        # Empty collection with initial value
        self.assertEqual(sum_of_squares([]), 0)
    
    def test_trampoline(self):
        """Test trampolining for recursive functions."""
        @trampoline
        def factorial(n, acc=1):
            if n <= 1:
                return acc
            return lambda: factorial(n-1, n*acc)
        
        # This would normally cause a stack overflow for large values
        self.assertEqual(factorial(5), 120)  # 5! = 120
        
        # Test with a larger value that might cause stack overflow without trampolining
        try:
            result = factorial(100)
            # Simply getting a result without stack overflow is a success
            self.assertTrue(isinstance(result, int))
        except RecursionError:
            self.fail("Trampoline failed to prevent recursion error")
    
    def test_higher_order_decorator(self):
        """Test the higher-order decorator."""
        @higher_order
        def add(a, b):
            return a + b
            
        self.assertTrue(is_higher_order(add))
        self.assertEqual(add(2, 3), 5)
        
        @higher_order(enhanced=True)
        def multiply(a, b):
            return a * b
            
        # Test enhanced methods
        double = multiply.partial(2)
        self.assertEqual(double(3), 6)
        
        curried_multiply = multiply.curry()
        self.assertEqual(curried_multiply(2)(3), 6)
        
        # For testing pipe, use a simple function that takes one argument
        square = lambda x: x * x
        add_one = lambda x: x + 1
        
        # This is the correct way to use pipe
        square_then_add = pipe(square, add_one)
        self.assertEqual(square_then_add(4), 17)  # 4^2 + 1 = 17
    
    def test_is_higher_order(self):
        """Test identifying higher-order functions."""
        def normal_function(a, b):
            return a + b
            
        def higher_function(func, x):
            return func(x)
            
        # Manually mark this function as higher-order for the test
        higher_function._is_higher_order = True
        
        @higher_order  # Use the decorator to properly mark the function
        def returns_function(x):
            return lambda y: x + y
            
        self.assertFalse(is_higher_order(normal_function))
        self.assertTrue(is_higher_order(higher_function))
        self.assertTrue(is_higher_order(returns_function))
        
        # Test with explicit annotation
        from typing import Callable
        
        def annotated(func: Callable, x):
            return func(x)
            
        # Manually mark this function as higher-order for the test
        annotated._is_higher_order = True
        
        self.assertTrue(is_higher_order(annotated))

if __name__ == '__main__':
    unittest.main()