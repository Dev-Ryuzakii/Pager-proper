"""
Markov chain language model for realistic casual chat decoy text.
Self-contained - no external APIs or model files needed.
Replaces template-based generator with a trained statistical model.
"""

import random
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

# ── Training corpus ────────────────────────────────────────────────────────────
# ~185 casual everyday English phrases across varied topics.
# Shared bigrams across sentences create branching that produces novel output.

_CORPUS: List[str] = [
    # Greetings / checking in
    "hey are you free tonight",
    "hey are you busy right now",
    "are you free this afternoon",
    "what are you up to later",
    "what are you doing this weekend",
    "just wanted to check in with you",
    "haven't heard from you in a while",
    "hope you're doing okay today",
    "hope everything is going well with you",
    "long time no talk how are you",
    "miss you let's catch up soon",
    "thinking about you today hope you're good",
    "been meaning to reach out forever",
    "how have you been doing lately",
    "how's everything going on your end",
    "just checking in hope things are good",
    "haven't talked properly in ages",
    "we should really catch up soon",
    "feel like we haven't spoken in forever",
    "you alright haven't seen you around",

    # Making plans
    "are you coming to the thing tonight",
    "can we meet up this weekend",
    "I'll be there around eight or so",
    "I'll pick you up around seven tonight",
    "let me know if that works for you",
    "we should grab coffee sometime this week",
    "are you free on Saturday morning",
    "want to do something this evening",
    "I'm heading out in about twenty minutes",
    "running a little late sorry be there soon",
    "should I bring anything when I come",
    "where do you want to eat tonight",
    "let's try somewhere different this time",
    "I booked a table for seven thirty",
    "what time are you thinking we leave",
    "we could leave around six to beat traffic",
    "are you driving or should I",
    "let me know what time you're ready",
    "I'll send you the address in a bit",
    "can you make it by noon",
    "sometime next week might work better for me",
    "would Friday work or is that too late",
    "we could do Sunday morning if you're free",
    "let's not leave it too long this time",
    "either Saturday or Sunday works for me",
    "we could make a day of it honestly",
    "I was thinking we could try that new spot",
    "are you bringing anyone else along",

    # Daily life
    "just got home from work completely drained",
    "traffic was absolutely terrible again today",
    "can you grab some milk on your way",
    "the dog has been barking all morning",
    "I made too much food want some",
    "my phone battery is almost dead again",
    "I left my keys at the office again",
    "need to stop at the store on the way",
    "it's freezing outside today bring a jacket",
    "finally nice weather after all that rain",
    "the weather has been so unpredictable lately",
    "can't sleep it's way too hot tonight",
    "got up really early today couldn't go back",
    "been running around all day need a break",
    "finally finished everything I needed to do",
    "the landlord came by to fix the heating",
    "spent all morning sorting out the apartment",
    "the hot water was out this morning",
    "I've been so busy this whole week",
    "need to sort out so many things today",
    "forgot to set my alarm again this morning",
    "managed to get everything done before noon",
    "I have an appointment this afternoon",
    "have to pick someone up from the airport",
    "the delivery was delayed again apparently",
    "the neighbours are being so loud tonight",
    "just finished a really long walk outside",
    "went to bed way too late last night",
    "had the weirdest dream last night",
    "been trying to sort this out all day",

    # Food
    "did you eat anything yet today",
    "I'm starving haven't eaten since morning",
    "tried that new place on the corner",
    "the food there was actually really good",
    "been craving pizza for the past few days",
    "let's just order in tonight I'm too tired",
    "are you cooking tonight or should we order",
    "I burned the rice again somehow",
    "made soup today it actually came out well",
    "you have to try the bakery on the high street",
    "the portions were huge we couldn't finish",
    "found this amazing little restaurant last week",
    "lunch was surprisingly good today actually",
    "need to stop eating so late at night",
    "made too much coffee again as usual",
    "the cafe near the office has great pastries",
    "just had the best meal honestly loved it",
    "should have eaten before we left",
    "I could really go for something warm right now",
    "thinking about cooking something proper tonight",
    "we went to that place you recommended",
    "they changed the menu and it's better now",

    # Work / school
    "had back to back meetings all morning long",
    "that presentation actually went really well",
    "boss needs the report done by tomorrow",
    "have so much work piled up right now",
    "finally finished that project late last night",
    "the interview felt like it went okay",
    "got the assignment done earlier than expected",
    "class got cancelled again this week",
    "the deadline got pushed to Friday thankfully",
    "study group is meeting at the library tonight",
    "working late again tonight unfortunately",
    "the client moved the call to next week",
    "meeting ran over by almost an hour",
    "waiting to hear back about the application",
    "just submitted everything before the deadline",
    "the new system keeps crashing for everyone",
    "training session ran all afternoon today",
    "been on calls since early this morning",
    "so much admin to get through today",
    "finally got some feedback on that project",
    "they want revisions done by end of week",
    "things at work have been pretty hectic",

    # Casual observations
    "saw something hilarious on the way here",
    "can you believe what actually happened today",
    "that was honestly so unexpected",
    "things are finally starting to calm down",
    "been meaning to reply to that for days",
    "time just flies by so fast these days",
    "feels like we never have enough time",
    "this week has been completely exhausting",
    "really looking forward to the weekend finally",
    "almost forgot to mention this earlier",
    "by the way did you see that thing",
    "good call I wouldn't have thought of that",
    "makes sense when you explain it like that",
    "totally forgot that was even happening today",
    "keep meaning to sort that out properly",
    "I keep putting it off and I really shouldn't",
    "this has been going on for weeks now",
    "thought it would be simple but it wasn't",
    "turns out it was easier than expected",
    "ended up being a whole thing today",
    "wasn't expecting that at all honestly",
    "so much going on at once right now",
    "thought I had more time than I actually did",
    "can't believe it's already that time of year",
    "didn't realise how late it had gotten",
    "finally got a moment to breathe today",

    # Short conversational replies
    "sounds good let me know",
    "okay I'll check and let you know",
    "on my way should be there soon",
    "give me about ten minutes",
    "okay see you there then",
    "got it I'll sort it out",
    "no problem at all don't worry about it",
    "let me check and I'll get back to you",
    "that works perfectly for me",
    "I'll figure something out don't stress",
    "sure just tell me when you're ready",
    "I'll handle it you don't need to worry",
    "we can figure out the rest later",
    "seriously though it was so funny",
    "I couldn't stop laughing the whole time",
    "never mind I worked it out",
    "actually that's a really good point",
    "fair enough that makes sense to me",
    "true I didn't think about it that way",
    "yeah no that's completely fair",
    "I was just about to say that",
    "that's exactly what I was thinking",

    # Entertainment / tech
    "have you watched the new series yet",
    "the last episode was not what I expected",
    "can't stop listening to this playlist lately",
    "you really have to read this article",
    "that documentary was actually really good",
    "they just announced it this morning",
    "the update broke everything again as usual",
    "my laptop has been running so slowly",
    "finally got it working after trying forever",
    "you should download that app it's so useful",
    "the game was incredible last night",
    "they just released the trailer for it",
    "everyone's been talking about it today",
    "worth watching if you get the chance",
    "heard really good things about it recently",
    "the second season is supposed to be even better",

    # Travel / outdoors
    "just got back from the whole trip yesterday",
    "the views there were absolutely incredible",
    "thinking about a short trip sometime soon",
    "need to get away from everything honestly",
    "the drive took ages but was worth it",
    "found the most amazing little spot there",
    "should have packed lighter for next time",
    "already planning the next trip actually",
    "the whole place was just stunning",
    "want to go back as soon as possible",
    "we hiked for hours and it was perfect",
    "the countryside was beautiful this time of year",
]

# ── Markov chain ───────────────────────────────────────────────────────────────

class _MarkovChain:
    """Bigram Markov chain trained on _CORPUS."""

    def __init__(self, corpus: List[str], n: int = 2):
        self._n = n
        self._chain: Dict[Tuple, List[str]] = defaultdict(list)
        self._starters: List[Tuple] = []
        for sentence in corpus:
            tokens = sentence.lower().split()
            if len(tokens) <= n:
                continue
            self._starters.append(tuple(tokens[:n]))
            for i in range(len(tokens) - n):
                key = tuple(tokens[i : i + n])
                self._chain[key].append(tokens[i + n])

    def generate(self, min_words: int = 5, max_words: int = 14) -> str:
        for _ in range(30):
            state = random.choice(self._starters)
            words = list(state)
            for _ in range(max_words - self._n):
                nexts = self._chain.get(state)
                if not nexts:
                    break
                nxt = random.choice(nexts)
                words.append(nxt)
                state = tuple(words[-self._n :])
            if len(words) >= min_words:
                text = " ".join(words)
                return text[0].upper() + text[1:]
        # Fallback: return a random corpus sentence
        return random.choice(_CORPUS).capitalize()


_MODEL: Optional[_MarkovChain] = None


def _model() -> _MarkovChain:
    global _MODEL
    if _MODEL is None:
        _MODEL = _MarkovChain(_CORPUS)
    return _MODEL


# ── Public interface (backward-compatible) ─────────────────────────────────────

class FakeTextGenerator:
    """
    Generates realistic casual chat decoy text using a Markov chain model.
    All methods keep their original signatures for drop-in compatibility.
    """

    @staticmethod
    def generate_sentence() -> str:
        return _model().generate(min_words=4, max_words=10)

    @staticmethod
    def generate_paragraph(sentence_count: int = 3) -> str:
        sentences = [_model().generate(min_words=5, max_words=12) for _ in range(sentence_count)]
        return " ".join(sentences)

    @staticmethod
    def generate_message_preview(length: int = 50) -> str:
        text = _model().generate(min_words=4, max_words=10)
        if len(text) <= length:
            return text
        cut = text[:length - 3].rsplit(" ", 1)[0]
        return cut + "..."

    @staticmethod
    def generate_decoy_text_for_message(encrypted_content: str) -> str:
        """Generate a unique, natural-sounding decoy for any message."""
        return _model().generate(min_words=5, max_words=13)
