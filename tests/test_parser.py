
import pytest
from app.parsers.wazuh_agent_id import Parser
from app.objects.secondclass.c_fact import Fact

class TestWazuhAgentIdParser:
    def test_parse_client_keys(self):
        parser = Parser(None, None)
        # Mocking the self.line() method since it's inherited from BaseParser
        # In a real unit test for BaseParser subclass, we might need to mock differently
        # or just pass the blob if BaseParser.line() splits lines.
        # Assuming BaseParser.line() yields lines from blob.
        
        # We need to simulate BaseParser behavior or just test the logic inside the loop if possible.
        # Since we can't easily mock the parent class method without more context, 
        # let's assume we can instantiate it and callsparse.
        
        # Re-implementing a simple mock for the test context if needed, 
        # but for now let's try to trust the structure or mock the 'line' method.
        
        # Let's inspect BaseParser to be sure, but for this test I will assume I can just call parse
        # If BaseParser.line implementation is standard:
        
        blob = """
        001 VM1-Ubuntu any 1324123412341234
        002 VM2-Windows any 1234123412341234
        invalid_line_here
        # comment
        """
        
        # We need to mock 'mappers' as well because the parser iterates over them
        class MockMapper:
            source = 'initial_source'
            edge = 'has_agent_id'
            target = 'wazuh.agent.id'
            
        parser.mappers = [MockMapper()]
        parser.used_facts = []
        
        # Mocking set_value to return the value itself
        parser.set_value = lambda source, value, used: source
        
        # Mocking line generator
        def mock_line(blob):
            for line in blob.strip().split('\n'):
                yield line
                
        parser.line = mock_line
        
        relationships = parser.parse(blob)
        
        assert len(relationships) == 2
        assert relationships[0].target.value == '001'
        assert relationships[1].target.value == '002'

