import unittest
import sys
import os
from werkzeug.datastructures import MultiDict

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# Import the decorated functions directly from httpbin
from httpbin.helpers import semiflatten, json_safe
from httpbin.utils import weighted_choice

class TestImmutableIntegration(unittest.TestCase):
    
    def test_semiflatten_immutability(self):
        """Test that semiflatten doesn't modify its input."""
        # Create a MultiDict
        multi_dict = MultiDict([('key1', 'value1'), ('key2', 'value2'), ('key3', 'value3a'), ('key3', 'value3b')])
        
        # Make a copy to compare later
        multi_dict_copy = MultiDict(multi_dict.items(multi=True))
        
        # Run the function
        result = semiflatten(multi_dict)
        
        # Verify original is unchanged
        self.assertEqual(sorted(multi_dict.items(multi=True)), sorted(multi_dict_copy.items(multi=True)))
        
        # Verify result is as expected
        self.assertEqual(result['key1'], 'value1')
        self.assertEqual(result['key2'], 'value2')
        self.assertEqual(result['key3'], ['value3a', 'value3b'])
    
    def test_weighted_choice_immutability(self):
        """Test that weighted_choice doesn't modify its input."""
        # Create input data
        choices = [('val1', 5), ('val2', 0.3), ('val3', 1)]
        choices_copy = [('val1', 5), ('val2', 0.3), ('val3', 1)]
        
        # Run the function multiple times
        for _ in range(10):
            result = weighted_choice(choices)
            
            # Verify the choices list is unchanged
            self.assertEqual(choices, choices_copy)
            
            # Verify result is one of the expected values
            self.assertIn(result, [choice[0] for choice in choices])
    
    def test_json_safe_immutability(self):
        """Test that json_safe doesn't modify its input."""
        # Create test data
        binary_data = b'\x00\x01\x02\x03\x04'
        binary_copy = b'\x00\x01\x02\x03\x04'
        
        # Run the function
        result = json_safe(binary_data)
        
        # Verify original is unchanged
        self.assertEqual(binary_data, binary_copy)
        
        # Verify result starts with data URI scheme
        self.assertTrue(result.startswith('data:application/octet-stream;base64,'))

if __name__ == '__main__':
    unittest.main()