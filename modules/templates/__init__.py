"""Data-driven technique templates (nuclei-style).

Each template is a dict describing an attack/check; the engine turns every
template into a registered scanner module. This lets the catalog scale to
hundreds of techniques as data — add a dict, get a new module.
"""
