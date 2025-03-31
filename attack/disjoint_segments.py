from collections.abc import Hashable, MutableSet

from icecream import ic
from functools import reduce
import json


class UserSet(Hashable, MutableSet):
    """
    A set that is hashable.
    """

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
    """
    A disjoint set of ranges.
    """

    @staticmethod
    def intersect(range1: range, range2: range) -> bool:
        """
        Returns True if the two ranges intersect.
        """
        if range1.start <= range2.start and range2.start < range1.stop:
            return True
        if range2.start <= range1.start and range1.start < range2.stop:
            return True
        return False

    @staticmethod
    def compare(M1, M2) -> bool:
        return str(M1) == str(M2)

    def add(self, item: range) -> None:
        """
        Adds a range to the disjoint set. If the range intersects with any of the existing ranges, it will merge them.
        """
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
        """
        Returns the total size of all the ranges in the disjoint set.
        """
        return reduce(lambda a, b: a + b, ((r.stop - r.start) for r in self.data))

    def smallest_inclusive(self) -> range:
        """
        Returns the smallest range that includes all the ranges in the disjoint set.
        """
        start = min(val.start for val in self.data)
        stop = max(val.stop for val in self.data)
        return range(start, stop)

    def len(self) -> int:
        """
        Returns the number of ranges in the disjoint set.
        """
        return len(self.data)

    def tolist(self) -> list[range]:
        """
        Returns the disjoint set as a list.
        """
        return list(self.data)

    def serialize(self) -> str:
        """
        Returns a JSON serialized version of the disjoint set.
        """
        return json.dumps([(val.start, val.stop) for val in self.data])

    @classmethod
    def deserialize(cls, data: str) -> "DisjointSegments":
        """
        Returns a DisjointSegments object from a JSON serialized string.
        """
        return cls(range(val[0], val[1]) for val in json.loads(data))

    def __str__(self) -> str:
        return self.serialize()


if __name__ == "__main__":
    dj = DisjointSegments()
    dj.add(range(2, 9))
    dj.add(range(13, 15))
    assert dj.size() == 9
    assert dj.smallest_inclusive() == range(2, 15)
    assert dj.len() == 2
    dj.add(range(7, 14))
    assert dj.size() == 13
    assert dj.smallest_inclusive() == range(2, 15)
    assert dj.len() == 1

    dj2 = DisjointSegments.deserialize(dj.serialize())
    assert dj == dj2
    assert dj is not dj2
    assert dj.data is not dj2.data
    assert dj.data == dj2.data
    assert DisjointSegments() != dj
