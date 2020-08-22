class WhiteList:
    def __init__(self, filename: str):
        self._whitelist = dict()
        with open(filename) as f:
            self._domains = [s.strip() for s in f.readlines()]
            # find duplicates

        if not self._domains:
            print("Please provide some domains in whitelist or disable it in config.ini")
            raise ValueError

        self.parse()

    def parse(self):
        for name in self._domains:
            domain = name.split('.')[::-1]
            # check for wildcard
            if domain[-1] == "*":
                domain = domain[:-1]
                t = self.nested_dict(domain, "*")
            else:
                t = self.nested_dict(domain, -1)
            key = next(iter(t.keys()))
            if not t.get(key, False):
                continue
            if not self._whitelist.get(key, False):
                self._whitelist[key] = t.get(key)
            else:
                try:
                    self._whitelist[key].update(t.get(key))
                except IndexError:
                    pass

    def nested_dict(self, data: list, value) -> dict:
        if len(data) == 1:
            return {data[0]: value}
        return {data[0]: self.nested_dict(data[1:], value)}

    def check_domain_in_whitelist(self, domain: str) -> bool:
        domain = domain.strip().split('.')
        c = self._whitelist
        while domain:
            subdomain = domain.pop()
            c = c.get(subdomain, False)
            if c == "*":
                return True
            if not c:
                return False
        return True
