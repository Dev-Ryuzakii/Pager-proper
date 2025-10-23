"""
Fake Text Generator for Secure Messaging System
Generates realistic-looking English text as placeholders for encrypted messages
"""

import random
import re
from typing import List, Dict

class FakeTextGenerator:
    """Generate realistic-looking English text for message placeholders"""
    
    # Common sentence patterns for realistic text
    SENTENCE_PATTERNS = [
        "The {noun} {verb} {adverb} in the {location}.",
        "{person} {verb} the {noun} {adverb} yesterday.",
        "A {adjective} {noun} was {verb} near the {location}.",
        "The {person} mentioned that the {noun} {verb} {adverb}.",
        "In the {location}, a {adjective} {noun} {verb} {adverb}.",
        "{person} will {verb} the {adjective} {noun} soon.",
        "The {noun} should {verb} {adverb} according to {person}.",
        "A {adjective} {noun} might {verb} in the {location}."
    ]
    
    # Word lists for generating realistic text
    WORDS = {
        "noun": [
            "project", "system", "application", "network", "database", "server", 
            "client", "interface", "protocol", "algorithm", "framework", "library",
            "module", "component", "service", "platform", "solution", "architecture",
            "design", "pattern", "method", "function", "class", "object", "variable",
            "parameter", "argument", "response", "request", "endpoint", "resource",
            "configuration", "setting", "option", "feature", "capability", "functionality",
            "process", "workflow", "task", "job", "operation", "transaction", "query",
            "command", "instruction", "directive", "order", "message", "notification"
        ],
        "verb": [
            "processes", "handles", "manages", "controls", "monitors", "tracks",
            "optimizes", "secures", "encrypts", "decrypts", "validates", "verifies",
            "authenticates", "authorizes", "routes", "transmits", "receives", "sends",
            "stores", "retrieves", "updates", "deletes", "creates", "generates",
            "transforms", "converts", "analyzes", "evaluates", "assesses", "reviews",
            "inspects", "examines", "checks", "tests", "debugs", "resolves", "fixes",
            "implements", "deploys", "configures", "initializes", "terminates", "shuts down"
        ],
        "adverb": [
            "efficiently", "securely", "effectively", "quickly", "reliably", "consistently",
            "automatically", "manually", "carefully", "thoroughly", "completely", "partially",
            "temporarily", "permanently", "immediately", "gradually", "smoothly", "seamlessly",
            "transparently", "safely", "accurately", "precisely", "correctly", "appropriately",
            "properly", "adequately", "sufficiently", "optimally", "maximally", "minimally"
        ],
        "adjective": [
            "secure", "efficient", "reliable", "scalable", "robust", "flexible",
            "modular", "extensible", "maintainable", "testable", "documented", "optimized",
            "distributed", "centralized", "synchronized", "asynchronous", "real-time", "batch",
            "encrypted", "authenticated", "authorized", "validated", "verified", "certified",
            "critical", "important", "essential", "necessary", "optional", "additional",
            "primary", "secondary", "tertiary", "temporary", "permanent", "dynamic"
        ],
        "location": [
            "server room", "data center", "cloud environment", "network segment", 
            "database cluster", "application layer", "service mesh", "API gateway",
            "load balancer", "firewall zone", "DMZ", "internal network", "external network",
            "VPN tunnel", "SSH connection", "TLS session", "SSL handshake", "authentication server",
            "authorization service", "message queue", "event bus", "cache layer", "storage system"
        ],
        "person": [
            "the administrator", "the developer", "the operator", "the engineer", 
            "the analyst", "the architect", "the manager", "the coordinator", "the specialist",
            "the technician", "the consultant", "the expert", "the team", "the department",
            "the organization", "the client", "the user", "the customer", "the stakeholder",
            "the supervisor", "the director", "the officer", "the representative"
        ]
    }
    
    @staticmethod
    def generate_sentence() -> str:
        """Generate a single realistic-looking sentence"""
        pattern = random.choice(FakeTextGenerator.SENTENCE_PATTERNS)
        
        # Replace placeholders with random words
        sentence = pattern
        for word_type, words in FakeTextGenerator.WORDS.items():
            placeholder = "{" + word_type + "}"
            if placeholder in sentence:
                word = random.choice(words)
                sentence = sentence.replace(placeholder, word, 1)
        
        # Capitalize first letter
        sentence = sentence[0].upper() + sentence[1:]
        
        # Add period if missing
        if not sentence.endswith('.'):
            sentence += '.'
            
        return sentence
    
    @staticmethod
    def generate_paragraph(sentence_count: int = 3) -> str:
        """Generate a paragraph with multiple sentences"""
        sentences = [FakeTextGenerator.generate_sentence() for _ in range(sentence_count)]
        return " ".join(sentences)
    
    @staticmethod
    def generate_message_preview(length: int = 50) -> str:
        """Generate a short message preview text"""
        # Generate a sentence and truncate to desired length
        sentence = FakeTextGenerator.generate_sentence()
        
        # If sentence is shorter than desired length, return as is
        if len(sentence) <= length:
            return sentence
        
        # Truncate and add ellipsis
        truncated = sentence[:length-3].strip()
        # Make sure we don't cut off in the middle of a word
        if ' ' in truncated:
            truncated = ' '.join(truncated.split(' ')[:-1])
        return truncated + "..."
    
    @staticmethod
    def generate_decoy_text_for_message(encrypted_content: str) -> str:
        """Generate decoy text based on the length and structure of the encrypted content"""
        # Get length of encrypted content
        content_length = len(encrypted_content)
        
        # Generate appropriate length decoy text
        if content_length < 50:
            return FakeTextGenerator.generate_message_preview(50)
        elif content_length < 100:
            return FakeTextGenerator.generate_message_preview(80)
        elif content_length < 200:
            return FakeTextGenerator.generate_paragraph(2)
        else:
            return FakeTextGenerator.generate_paragraph(3)

# Example usage
if __name__ == "__main__":
    # Generate some sample fake text
    generator = FakeTextGenerator()
    
    print("Sample fake message previews:")
    for i in range(5):
        preview = generator.generate_message_preview()
        print(f"{i+1}. {preview}")
    
    print("\nSample paragraphs:")
    for i in range(3):
        paragraph = generator.generate_paragraph()
        print(f"{i+1}. {paragraph}")
    
    # Example with encrypted content
    sample_encrypted = "ENCRYPTED_CONTENT_WITH_RANDOM_CHARACTERS_AND_NUMBERS_1234567890"
    decoy = generator.generate_decoy_text_for_message(sample_encrypted)
    print(f"\nDecoy for encrypted content: {decoy}")