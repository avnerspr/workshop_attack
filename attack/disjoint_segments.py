from collections.abc import Hashable, MutableSet

from icecream import ic
from functools import reduce

class UserSet(Hashable, MutableSet):
    __hash__ = MutableSet._hash

    def __init__(self, iterable=()):
        self.data: set[range] = set(iterable)

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
        if item.stop <= item.start:
            return
        to_merge = {
            value for value in self.data if DisjointSegments.intersect(value, item)
        }
        self.data.difference_update(to_merge)
        to_merge.add(item)
        start = min(val.start for val in to_merge)
        stop = max(val.stop for val in to_merge)
        self.data.add(range(start, stop))
    
    def size(self) -> int:
        return reduce(lambda a, b: a + b, ((r.stop - r.start) for r in self.data))
        
        

if __name__ == "__main__":
    dj = DisjointSegments()
    dj.add(range(2, 9))
    ic(dj)
    dj.add(range(13, 15))
    ic(dj)
    dj.add(range(7, 14))
    ic(dj)
    