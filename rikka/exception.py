class ConfigMissing(Exception):
    """missing necessary config"""
    def __init__(self, msg):
        super().__init__("missing necessary config '{}'".format(msg))
