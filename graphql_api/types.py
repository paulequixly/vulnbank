import graphene
from graphene.types import JSONString


class UserType(graphene.ObjectType):
    """
    User account information
    Vulnerability: Exposes sensitive fields like password, reset_pin
    """
    id = graphene.Int()
    username = graphene.String()
    password = graphene.String()  # Vulnerability: password exposed
    account_number = graphene.String()
    balance = graphene.Float()
    is_admin = graphene.Boolean()
    profile_picture = graphene.String()
    reset_pin = graphene.String()  # Vulnerability: reset pin exposed


class LoanType(graphene.ObjectType):
    """Loan information"""
    id = graphene.Int()
    user_id = graphene.Int()
    amount = graphene.Float()
    status = graphene.String()


class TransactionType(graphene.ObjectType):
    """Transaction record"""
    id = graphene.Int()
    from_account = graphene.String()
    to_account = graphene.String()
    amount = graphene.Float()
    timestamp = graphene.String()
    transaction_type = graphene.String()
    description = graphene.String()


class VirtualCardType(graphene.ObjectType):
    """
    Virtual card information
    Vulnerability: Exposes CVV and full card number
    """
    id = graphene.Int()
    user_id = graphene.Int()
    card_number = graphene.String()  # Vulnerability: card number exposed
    cvv = graphene.String()  # Vulnerability: CVV exposed
    expiry_date = graphene.String()
    card_limit = graphene.Float()
    current_balance = graphene.Float()
    is_frozen = graphene.Boolean()
    is_active = graphene.Boolean()
    created_at = graphene.String()
    last_used_at = graphene.String()
    card_type = graphene.String()


class CardTransactionType(graphene.ObjectType):
    """Card transaction record"""
    id = graphene.Int()
    card_id = graphene.Int()
    amount = graphene.Float()
    merchant_name = graphene.String()
    transaction_type = graphene.String()
    status = graphene.String()
    timestamp = graphene.String()
    description = graphene.String()


class BillCategoryType(graphene.ObjectType):
    """Bill payment category"""
    id = graphene.Int()
    name = graphene.String()
    description = graphene.String()
    is_active = graphene.Boolean()


class BillerType(graphene.ObjectType):
    """
    Biller information
    Vulnerability: Exposes biller account numbers
    """
    id = graphene.Int()
    category_id = graphene.Int()
    name = graphene.String()
    account_number = graphene.String()  # Vulnerability: account number exposed
    description = graphene.String()
    minimum_amount = graphene.Float()
    maximum_amount = graphene.Float()
    is_active = graphene.Boolean()


class BillPaymentType(graphene.ObjectType):
    """Bill payment record"""
    id = graphene.Int()
    user_id = graphene.Int()
    biller_id = graphene.Int()
    amount = graphene.Float()
    payment_method = graphene.String()
    card_id = graphene.Int()
    reference_number = graphene.String()
    status = graphene.String()
    created_at = graphene.String()
    processed_at = graphene.String()
    description = graphene.String()
    biller_name = graphene.String()
    category_name = graphene.String()


# Response types for mutations
class AuthPayloadType(graphene.ObjectType):
    """
    Authentication response with JWT token
    Vulnerability: Exposes debug info
    """
    status = graphene.String()
    message = graphene.String()
    token = graphene.String()
    account_number = graphene.String()
    is_admin = graphene.Boolean()
    debug_info = JSONString()  # Vulnerability: debug info exposed


class TransferResultType(graphene.ObjectType):
    """Transfer operation result"""
    status = graphene.String()
    message = graphene.String()
    new_balance = graphene.Float()


class CardCreateResultType(graphene.ObjectType):
    """
    Virtual card creation result
    Vulnerability: Exposes CVV and card number
    """
    status = graphene.String()
    message = graphene.String()
    card_number = graphene.String()
    cvv = graphene.String()  # Vulnerability: CVV exposed
    expiry_date = graphene.String()
    card_limit = graphene.Float()
    card_type = graphene.String()


class CardUpdateResultType(graphene.ObjectType):
    """Card update result"""
    status = graphene.String()
    message = graphene.String()
    is_frozen = graphene.Boolean()
    card_limit = graphene.Float()
    current_balance = graphene.Float()


class BillPaymentResultType(graphene.ObjectType):
    """Bill payment result"""
    status = graphene.String()
    message = graphene.String()
    reference = graphene.String()
    amount = graphene.Float()
    payment_method = graphene.String()
    timestamp = graphene.String()


class LoanResultType(graphene.ObjectType):
    """
    Loan request/approval result
    Vulnerability: Exposes debug info
    """
    status = graphene.String()
    message = graphene.String()
    loan_id = graphene.Int()
    amount = graphene.Float()
    debug_info = JSONString()  # Vulnerability: debug info exposed


class DeleteResultType(graphene.ObjectType):
    """Delete operation result"""
    status = graphene.String()
    message = graphene.String()


# =============================================================================
# BOLA DEMO TYPES - Multi-Stage Horizontal Privilege Escalation
# =============================================================================

class AccountProfileType(graphene.ObjectType):
    """
    Account profile information - Stage 2 of BOLA attack
    Vulnerability: No ownership check - any account can be looked up
    """
    user_id = graphene.Int()  # Leaked: enables Stage 3
    username = graphene.String()  # Leaked: PII
    account_number = graphene.String()
    profile_picture = graphene.String()
    account_created = graphene.String()
    account_type = graphene.String()  # 'standard' or 'premium'


class StatementTransactionType(graphene.ObjectType):
    """Individual transaction within a statement"""
    date = graphene.String()
    description = graphene.String()
    amount = graphene.Float()
    balance_after = graphene.Float()
    transaction_type = graphene.String()


class AccountStatementType(graphene.ObjectType):
    """
    Full account statement - Stage 3 of BOLA attack
    Vulnerability: No authorization check - exposes complete financial history
    """
    id = graphene.Int()
    user_id = graphene.Int()
    month = graphene.String()
    opening_balance = graphene.Float()
    closing_balance = graphene.Float()
    total_credits = graphene.Float()
    total_debits = graphene.Float()
    statement_date = graphene.String()
    notes = graphene.String()  # Vulnerability: May contain sensitive info
    transactions = graphene.List(StatementTransactionType)
