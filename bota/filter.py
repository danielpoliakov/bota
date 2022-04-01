"""
    Endpoint filtering.
"""

import ipaddress
from abc import ABC, abstractmethod
from enum import Enum


class FilterBy(Enum):
    """Filtering property enumeration."""

    IP = 1
    MAC = 2
    ANY = 3


class Filter(ABC):
    """Filter abstract base class."""

    #: Filter by anything.
    filter_by = FilterBy.ANY

    @abstractmethod
    def apply(self, item):
        """Abstract apply method.

        Args:
            item (object): Filter specific object.

        Raises:
            NotImplementedError: Abstract method.
        """
        raise NotImplementedError


class ListFilter(Filter):
    """Filter for lists of generic items.

    Args:
        items (list): List of sortable objects.
    """

    #: Filter by anything.
    filter_by = FilterBy.ANY

    def __init__(self, items):
        self.items = sorted(items)

    def apply(self, item):
        """Overridden apply method for generic lists.

        Args:
            item (object): Sortable object.

        Returns:
            bool: True if item found in the list.
        """
        return self.binary_search(item)

    def binary_search(self, item):
        low = 0
        high = len(self.items) - 1

        while low <= high:
            mid = low + (high - low) // 2
            item_mid = self.items[mid]

            if item == item_mid:
                return True
            elif item < item_mid:
                high = mid - 1
            elif item > item_mid:
                low = mid + 1

        return False


class IPListFilter(ListFilter):
    """Filter for lists of IP addresses.

    Args:
        ip_list (list): List of string represented IP addresses.
    """

    #: Filter by IP addresses.
    filter_by = FilterBy.IP

    def __init__(self, ip_list):
        self.items = sorted([int(ipaddress.ip_address(x)) for x in ip_list])

    def apply(self, ip):
        """Apply method for lists of IP addresses.

        Args:
            ip (string): String represented IP address.

        Returns:
            bool: True if IP address found in the list.
        """
        return self.binary_search(int(ipaddress.ip_address(ip)))


class MACListFilter(ListFilter):
    """Filter for lists of MAC addresses.

    Args:
        mac_list (list): List of string represented MAC addresess.
    """

    #: Filter by MAC addresses.
    filter_by = FilterBy.MAC

    def __init__(self, mac_list):
        self.items = sorted([int(x.replace(":", ""), 16) for x in mac_list])

    def apply(self, mac):
        """Apply method for the list of MAC addresses.

        Args:
            mac (string): String represented MAC address.

        Returns:
            bool: True if MAC address found in the list.
        """
        return self.binary_search(int(mac.replace(":", ""), 16))


class IPRangeFilter(Filter):
    """Filter for IP ranges.

    Args:
        ip_range (string): CIDR representation of an IP range.
    """

    #: Filter by IP addresses.
    filter_by = FilterBy.IP

    def __init__(self, ip_range):
        self.ip_range = ip_range

    def apply(self, ip):
        """Apply method for the ranges of IP addresses.

        Args:
            ip (string): String represented IP address.

        Returns:
            bool: True if IP address in the range.
        """
        return ipaddress.ip_address(ip) in ipaddress.ip_network(self.ip_range)
