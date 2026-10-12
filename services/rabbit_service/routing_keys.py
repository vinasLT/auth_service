from enum import Enum


class RoutingKeys(str, Enum):
    BID_PLACED = 'auction.bid.placed'
    PURCHASE_CREATED = 'auction.purchase.created'
    PURCHASE_PAID = 'auction.purchase.paid'
    PURCHASE_CANCELLED = 'auction.purchase.cancelled'
