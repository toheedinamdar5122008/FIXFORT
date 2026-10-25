"""Clearly-identified local test doubles for FixFort's Brain.

These stand in for infrastructure owned by other teammates so Person A's
pipeline can be built and proven end-to-end offline:

  * mock_app.MockApp        -> stands in for Person C's victim website
  * mock_shield.MockShield  -> stands in for Person B's shield-control interface
  * transport.MockTransport -> routes exam HTTP calls through shield + app

They are deterministic and in-process. They are NOT used in production: at the
venue the same calls hit the real Dockerised ModSecurity shield and Flask app.
"""
