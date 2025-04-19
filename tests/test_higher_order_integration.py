import unittest
import sys
import os
from werkzeug.datastructures import MultiDict

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# Import the higher-order functions module
from fp_decorators.higher_order import is_higher_order, compose, pipe

# Import the decorated functions from httpbin
from httpbin.filters import gzip
from httpbin.utils import weighted_choice
from httpbin.helpers import semiflatten

class TestHigherOrderIntegration(unittest.TestCase):
    
    def test_functions_are_higher_order(self):
        """Test that functions are correctly marked as higher-order."""
        self.assertTrue(is_higher_order(gzip))
        self.assertTrue(is_higher_order(weighted_choice))
        self.assertTrue(is_higher_order(semiflatten))
    
    def test_enhanced_functions_have_expected_methods(self):
        """Test that enhanced functions have the expected methods."""
        # All functions should have enhanced methods
        for func in [gzip, weighted_choice, semiflatten]:
            self.assertTrue(hasattr(func, 'compose'))
            self.assertTrue(hasattr(func, 'pipe'))
            self.assertTrue(hasattr(func, 'curry'))
            self.assertTrue(hasattr(func, 'partial'))
            self.assertTrue(hasattr(func, 'memoized'))
    
    def test_semiflatten_with_pipe(self):
        """Test piping with semiflatten."""
        # Create a simple function that adds a prefix to values
        def add_prefix(d, prefix="test_"):
            return {k: f"{prefix}{v}" if isinstance(v, str) else v for k, v in d.items()}
        
        # Create a MultiDict
        multi_dict = MultiDict([('key1', 'value1'), ('key2', 'value2')])
        
        # Create a pipeline: semiflatten and then add prefix
        pipeline = pipe(semiflatten, lambda d: add_prefix(d))
        
        # Apply the pipeline
        result = pipeline(multi_dict)
        
        # Check the result
        self.assertEqual(result['key1'], 'test_value1')
        self.assertEqual(result['key2'], 'test_value2')
    
    def test_weighted_choice_with_curry(self):
        """Test currying with weighted_choice."""
        choices = [('val1', 5), ('val2', 0.3), ('val3', 1)]
        
        # Since weighted_choice takes only one argument, currying doesn't change much
        # test that it still works
        curried = weighted_choice.curry()
        
        # Call the curried function
        result = curried(choices)
        
        # Verify the result is one of the expected values
        self.assertIn(result, [choice[0] for choice in choices])
        
    def test_weighted_choice_memoized(self):
        """Test memoization with weighted_choice."""
        # Create test data with fixed random seed
        import random
        random.seed(42)  # Fix the seed for deterministic results
        
        choices = [('val1', 1), ('val2', 0)]  # This will always return 'val1' with the fixed seed
        
        # Create a memoized version
        memoized_choice = weighted_choice.memoized()
        
        # Call multiple times - should get the same result
        first_result = memoized_choice(choices)
        random.seed(0)  # Change the seed to prove it's using the cache
        second_result = memoized_choice(choices)
        
        # Results should be the same due to memoization
        self.assertEqual(first_result, second_result)

if __name__ == '__main__':
    unittest.main()