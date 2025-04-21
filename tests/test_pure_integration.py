import unittest
import sys
import os
import json
import random
from unittest.mock import patch
import re
import base64

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# Import the functions with @pure decorator already applied
from httpbin.utils import weighted_choice
from httpbin.helpers import json_safe, H, HA1, HA2, semiflatten
from httpbin.structures import CaseInsensitiveDict

class TestPureHttpbinFunctions(unittest.TestCase):
    
    def test_weighted_choice_is_pure(self):
        """Test that weighted_choice with @pure decorator is functioning correctly."""
        choices = [('val1', 5), ('val2', 0.3), ('val3', 1)]
        
        # Set a fixed seed to make results deterministic
        random.seed(42)
        result1 = weighted_choice(choices)
        
        # Input should not be modified
        original_choices = [('val1', 5), ('val2', 0.3), ('val3', 1)]
        weighted_choice(original_choices)
        self.assertEqual(original_choices, [('val1', 5), ('val2', 0.3), ('val3', 1)])
        
        # Function should return a value from the choices
        self.assertIn(result1, ['val1', 'val2', 'val3'])
    
    def test_json_safe_is_pure(self):
        """Test that json_safe with @pure decorator is functioning correctly."""
        # Test with normal string
        normal_str = "test string"
        result = json_safe(normal_str.encode('utf-8'))
        self.assertEqual(result, normal_str)
        
        # Test with binary data
        binary_data = b'\x00\x01\x02\x03'
        result = json_safe(binary_data)
        self.assertTrue(result.startswith('data:application/octet-stream;base64,'))
        
        # Verify correct data URL format for binary data
        content_type = 'application/custom'
        result = json_safe(binary_data, content_type)
        self.assertTrue(result.startswith(f'data:{content_type};base64,'))
        
        # Verify we can decode the base64 part
        base64_data = result.split(',')[1]
        decoded = base64.b64decode(base64_data)
        self.assertEqual(decoded, binary_data)
        
        # Input should not be modified
        test_input = b"test input"
        json_safe(test_input)
        self.assertEqual(test_input, b"test input")
    
    def test_H_is_pure(self):
        """Test that H with @pure decorator is functioning correctly."""
        test_data = b"test data"
        
        # Test MD5 (default)
        md5_result = H(test_data, 'MD5')
        self.assertTrue(all(c in '0123456789abcdef' for c in md5_result))
        self.assertEqual(len(md5_result), 32)  # MD5 produces 32-char hex string
        
        # Test SHA-256
        sha256_result = H(test_data, 'SHA-256')
        self.assertTrue(all(c in '0123456789abcdef' for c in sha256_result))
        self.assertEqual(len(sha256_result), 64)  # SHA-256 produces 64-char hex string
        
        # Test SHA-512
        sha512_result = H(test_data, 'SHA-512')
        self.assertTrue(all(c in '0123456789abcdef' for c in sha512_result))
        self.assertEqual(len(sha512_result), 128)  # SHA-512 produces 128-char hex string
        
        # Input should not be modified
        test_input = b"test input"
        H(test_input, 'MD5')
        self.assertEqual(test_input, b"test input")
    
    def test_HA1_is_pure(self):
        """Test that HA1 with @pure decorator is functioning correctly."""
        realm = "test_realm"
        username = "test_user"
        password = "test_pass"
        
        # Test with MD5
        md5_result = HA1(realm, username, password, 'MD5')
        self.assertTrue(all(c in '0123456789abcdef' for c in md5_result))
        self.assertEqual(len(md5_result), 32)
        
        # Test with SHA-256
        sha256_result = HA1(realm, username, password, 'SHA-256')
        self.assertTrue(all(c in '0123456789abcdef' for c in sha256_result))
        self.assertEqual(len(sha256_result), 64)
        
        # Test with empty realm
        empty_realm_result = HA1('', username, password, 'MD5')
        self.assertTrue(all(c in '0123456789abcdef' for c in empty_realm_result))
        self.assertEqual(len(empty_realm_result), 32)
        
        # Calling with same inputs should yield same results
        md5_result2 = HA1(realm, username, password, 'MD5')
        self.assertEqual(md5_result, md5_result2)
    
    def test_HA2_is_pure(self):
        """Test that HA2 with @pure decorator is functioning correctly."""
        # Test with qop=auth
        credentials = {"qop": "auth"}
        request = {"method": "GET", "uri": "/test"}
        
        auth_result = HA2(credentials, request, 'MD5')
        self.assertTrue(all(c in '0123456789abcdef' for c in auth_result))
        self.assertEqual(len(auth_result), 32)
        
        # Test with qop=None
        credentials = {}
        no_qop_result = HA2(credentials, request, 'MD5')
        self.assertTrue(all(c in '0123456789abcdef' for c in no_qop_result))
        self.assertEqual(len(no_qop_result), 32)
        
        # Test with qop=auth-int
        credentials = {"qop": "auth-int"}
        request = {"method": "POST", "uri": "/test", "body": b"request body"}
        
        auth_int_result = HA2(credentials, request, 'MD5')
        self.assertTrue(all(c in '0123456789abcdef' for c in auth_int_result))
        self.assertEqual(len(auth_int_result), 32)
        
        # Test invalid qop raises ValueError
        credentials = {"qop": "invalid"}
        with self.assertRaises(ValueError):
            HA2(credentials, request, 'MD5')
        
        # Inputs should not be modified
        credentials = {"qop": "auth"}
        request = {"method": "GET", "uri": "/test"}
        original_credentials = dict(credentials)
        original_request = dict(request)
        
        HA2(credentials, request, 'MD5')
        self.assertEqual(credentials, original_credentials)
        self.assertEqual(request, original_request)
    
    def test_semiflatten_is_pure(self):
        """Test that semiflatten with @pure decorator is functioning correctly."""
        # Create a class similar to MultiDict for testing
        class MockMultiDict:
            def __init__(self, items):
                self.items = items
                
            def to_dict(self, flat=True):
                result = {}
                for k, v in self.items:
                    if k in result:
                        result[k].append(v)
                    else:
                        result[k] = [v]
                return result
        
        # Test with multi-value dict
        multi = MockMultiDict([('key1', 'value1'), ('key2', 'value2'), ('key1', 'value3')])
        result = semiflatten(multi)
        
        # key1 should have list since it has multiple values
        self.assertEqual(result['key1'], ['value1', 'value3'])
        # key2 should have single value
        self.assertEqual(result['key2'], 'value2')
        
        # Test with None
        self.assertEqual(semiflatten(None), None)
        
        # Create another dict to test inputs aren't modified
        test_dict = MockMultiDict([('key1', 'value1')])
        original_items = list(test_dict.items)
        semiflatten(test_dict)
        self.assertEqual(test_dict.items, original_items)
    
    def test_case_insensitive_dict_lower_keys_is_pure(self):
        """Test that CaseInsensitiveDict._lower_keys with @pure decorator is functioning correctly."""
        # Create a case insensitive dict
        headers = CaseInsensitiveDict()
        headers['Content-Type'] = 'application/json'
        headers['User-Agent'] = 'test-agent'
        
        # Test lower_keys returns correct values
        lower_keys = headers._lower_keys()
        self.assertEqual(set(lower_keys), {'content-type', 'user-agent'})
        
        # Verify dict is not modified
        self.assertEqual(headers['Content-Type'], 'application/json')
        self.assertEqual(headers['User-Agent'], 'test-agent')
        
        # Verify case-insensitive access works
        self.assertEqual(headers['content-type'], 'application/json')
        self.assertEqual(headers['user-agent'], 'test-agent')
    
    def test_integration_with_flask_app(self):
        """
        Integration test simulating how these pure functions would be used together.
        """
        # Simulate digest auth flow
        realm = "httpbin"
        username = "user"
        password = "pass"
        credentials = {"qop": "auth"}
        request = {"method": "GET", "uri": "/digest-auth/auth/user/pass"}
        
        ha1 = HA1(realm, username, password, 'MD5')
        ha2 = HA2(credentials, request, 'MD5')
        
        # Verify the hash values are hexadecimal strings of the right length
        self.assertTrue(all(c in '0123456789abcdef' for c in ha1))
        self.assertEqual(len(ha1), 32)  # MD5 produces 32-char hex string
        
        self.assertTrue(all(c in '0123456789abcdef' for c in ha2))
        self.assertEqual(len(ha2), 32)
        
        # Simulate weighted choice for status codes
        choices = [(200, 0.5), (404, 0.3), (500, 0.2)]
        status = weighted_choice(choices)
        self.assertIn(status, [200, 404, 500])
        
        # Simulate JSON encoding of binary data
        binary_data = os.urandom(20)  # Generate some random binary data
        json_encoded = json_safe(binary_data)
        self.assertTrue(json_encoded.startswith('data:application/octet-stream;base64,'))

if __name__ == '__main__':
    unittest.main()