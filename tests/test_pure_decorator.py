import unittest
import logging
import random
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from fp_decorators.pure import pure

class TestPureDecorator(unittest.TestCase):
    
    def test_pure_function_passes(self):
        """A pure function should pass without error."""
        
        @pure
        def add(a, b):
            return a + b
        
        self.assertEqual(add(5, 3), 8)
    
    def test_function_modifying_argument(self):
        """A function modifying its arguments should be detected as impure."""
        
        @pure
        def impure_list_append(lst, item):
            lst.append(item)  # Side effect - modifies input
            return lst
        
        with self.assertRaises(ValueError):
            my_list = [1, 2, 3]
            impure_list_append(my_list, 4)
    
    def test_function_modifying_global(self):
        """A function modifying a global variable should be detected as impure."""

        # Define global_counter in the global scope, not in the method
        global global_counter
        global_counter = 0

        @pure
        def impure_counter(increment):
            global global_counter
            global_counter += increment
            return global_counter

        with self.assertRaises(ValueError):
            impure_counter(1)
    
    def test_random_allowed(self):
        """Test that random is allowed when specified."""
        
        @pure(allow_random=True)
        def random_function():
            return random.randint(1, 100)
        
        # This should not raise
        result = random_function()
        self.assertTrue(1 <= result <= 100)
    
    def test_logger_allowed(self):
        """Test that logging is allowed by default."""
        
        logger = logging.getLogger("test")
        
        @pure
        def function_with_logging(input_val, log):
            log.info(f"Processing {input_val}")
            return input_val * 2
        
        # This should not raise
        self.assertEqual(function_with_logging(5, logger), 10)
    
    def test_ignore_params(self):
        """Test that specified parameters can be modified."""
        
        @pure(ignore_params=["output_list"])
        def append_to_output(item, output_list):
            output_list.append(item)
            return output_list
        
        output = []
        # This should not raise despite modifying output_list
        append_to_output(10, output)
        self.assertEqual(output, [10])

if __name__ == '__main__':
    unittest.main()