from enum import Enum


class RoutingKeys(str, Enum):
    BID_PLACED = 'auction.bid.placed'
    BID_PAID = 'bid.paid'


class ReferralPublishRoutingKeys(str, Enum):
    REWARD_APPROVED = 'referral.reward.approved'
