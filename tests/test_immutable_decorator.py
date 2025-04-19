import unittest
import sys
import os
import copy

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from fp_decorators.immutable import immutable

class TestImmutableDecorator(unittest.TestCase):
    
    def test_immutable_function_passes(self):
        """A function that doesn't modify inputs should pass."""
        
        @immutable
        def add_to_list(lst):
            result = lst.copy()
            result.append(4)
            return result
        
        input_list = [1, 2, 3]
        result = add_to_list(input_list)
        self.assertEqual(input_list, [1, 2, 3])  # Original unchanged
        self.assertEqual(result, [1, 2, 3, 4])   # New list returned
    
    def test_immutable_function_multiple_args(self):
        """A function with multiple arguments should work."""
        
        @immutable
        def merge_dicts(dict1, dict2):
            result = dict1.copy()
            result.update(dict2)
            return result
        
        d1 = {"a": 1, "b": 2}
        d2 = {"c": 3, "d": 4}
        result = merge_dicts(d1, d2)
        self.assertEqual(d1, {"a": 1, "b": 2})  # Original unchanged
        self.assertEqual(d2, {"c": 3, "d": 4})  # Original unchanged
        self.assertEqual(result, {"a": 1, "b": 2, "c": 3, "d": 4})
    
    def test_immutability_violation_detected(self):
        """A function modifying inputs should be detected as immutability violation."""
        
        @immutable
        def bad_add_to_list(lst):
            lst.append(4)  # Modifies input!
            return lst
        
        with self.assertRaises(ValueError):
            bad_add_to_list([1, 2, 3])
    
    def test_freeze_input_parameter(self):
        """When freeze_input is True, inputs should be converted to immutable types."""
        
        @immutable(freeze_input=True)
        def process_collection(collection):
            # This should receive a tuple instead of a list
            self.assertIsInstance(collection, tuple)
            return collection
        
        result = process_collection([1, 2, 3])
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, (1, 2, 3))
    
    def test_nested_mutable_structures(self):
        """Decorator should handle nested mutable structures."""
        
        @immutable
        def process_nested(data):
            result = copy.deepcopy(data)
            result['list'].append(4)
            result['dict']['new'] = 'value'
            return result
        
        original = {'list': [1, 2, 3], 'dict': {'a': 1}}
        result = process_nested(original)
        
        # Original should be unchanged
        self.assertEqual(original, {'list': [1, 2, 3], 'dict': {'a': 1}})
        
        # Result should have the modifications
        self.assertEqual(result, {'list': [1, 2, 3, 4], 'dict': {'a': 1, 'new': 'value'}})

if __name__ == '__main__':
    unittest.main()