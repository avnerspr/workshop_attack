from collections.abc import Hashable, MutableSet


from collections.abc import Hashable, MutableSet


class UserSet(Hashable, MutableSet):
    __hash__ = MutableSet._hash

    def __init__(self, iterable=()):
        self.data = set(iterable)

    def __contains__(self, value):
        return value in self.data

    def __iter__(self):
        return iter(self.data)

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return repr(self.data)

    def add(self, item):
        self.data.add(item)

    def discard(self, item):
        self.data.discard(item)


class DisjointSegments(UserSet):

    @staticmethod
    def intersect(range1: range, range2: range) -> bool:
        if range1.start <= range2.start and range2.start < range1.stop:
            return True
        if range2.start <= range1.start and range1.start < range2.stop:
            return True
        return False

    def add(self, item: range):
        assert isinstance(item, range)
        to_merge = {
            value for value in self.data if DisjointSegments.intersect(value, item)
        }
        self.data.difference_update(to_merge)
        to_merge.add(item)
        start = min(val.start for val in to_merge)
        stop = max(val.start for val in to_merge)
        self.data.add(range(start, stop))
