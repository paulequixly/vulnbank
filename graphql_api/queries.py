import graphene
from database import execute_query
from .types import (
    UserType, LoanType, TransactionType, VirtualCardType,
    CardTransactionType, BillCategoryType, BillerType, BillPaymentType
)


class Query(graphene.ObjectType):
    """
    GraphQL Query definitions for VulnBank
    Multiple intentional vulnerabilities for security education
    """

    # Account queries
    check_balance = graphene.Field(
        UserType,
        account_number=graphene.String(required=True),
        description="Check balance by account number. Vulnerability: BOLA, SQL injection"
    )

    # Transaction queries
    transactions = graphene.List(
        TransactionType,
        account_number=graphene.String(required=True),
        description="Get transaction history. Vulnerability: BOLA, SQL injection, no auth"
    )

    # Virtual card queries
    my_virtual_cards = graphene.List(
        VirtualCardType,
        description="Get current user's virtual cards. Requires authentication."
    )

    card_transactions = graphene.List(
        CardTransactionType,
        card_id=graphene.Int(required=True),
        description="Get card transactions. Vulnerability: BOLA - no ownership check"
    )

    # Bill payment queries
    bill_categories = graphene.List(
        BillCategoryType,
        description="Get bill payment categories. Public endpoint."
    )

    billers_by_category = graphene.List(
        BillerType,
        category_id=graphene.Int(required=True),
        description="Get billers by category. Vulnerability: SQL injection"
    )

    payment_history = graphene.List(
        BillPaymentType,
        description="Get payment history. Requires authentication."
    )

    # User/Admin queries
    user = graphene.Field(
        UserType,
        username=graphene.String(),
        description="Get user by username. Vulnerability: SQL injection"
    )

    all_users = graphene.List(
        UserType,
        description="List all users. Vulnerability: No auth, exposes passwords"
    )

    pending_loans = graphene.List(
        LoanType,
        description="Get pending loans. Should require admin."
    )

    def resolve_check_balance(self, info, account_number):
        """
        Vulnerability: BOLA - no authentication check
        Vulnerability: SQL injection - using string interpolation
        """
        query = f"SELECT * FROM users WHERE account_number='{account_number}'"
        result = execute_query(query)
        if result and len(result) > 0:
            row = result[0]
            return UserType(
                id=row[0],
                username=row[1],
                password=row[2],  # Vulnerability: exposing password
                account_number=row[3],
                balance=float(row[4]) if row[4] else 0.0,
                is_admin=bool(row[5]) if len(row) > 5 else False,
                profile_picture=row[6] if len(row) > 6 else None,
                reset_pin=row[7] if len(row) > 7 else None
            )
        return None

    def resolve_transactions(self, info, account_number):
        """
        Vulnerability: BOLA - no authentication required
        Vulnerability: SQL injection
        """
        query = f"""
            SELECT * FROM transactions
            WHERE from_account='{account_number}' OR to_account='{account_number}'
            ORDER BY timestamp DESC
        """
        results = execute_query(query)
        return [TransactionType(
            id=t[0],
            from_account=t[1],
            to_account=t[2],
            amount=float(t[3]),
            timestamp=str(t[4]),
            transaction_type=t[5],
            description=t[6]
        ) for t in results] if results else []

    def resolve_my_virtual_cards(self, info):
        """Get current user's virtual cards - requires authentication"""
        current_user = info.context.get('current_user')
        if not current_user:
            return []

        query = f"SELECT * FROM virtual_cards WHERE user_id = {current_user['user_id']}"
        results = execute_query(query)

        return [VirtualCardType(
            id=c[0],
            user_id=c[1],
            card_number=c[2],
            cvv=c[3],  # Vulnerability: exposing CVV
            expiry_date=c[4],
            card_limit=float(c[5]) if c[5] else 1000.0,
            current_balance=float(c[6]) if c[6] else 0.0,
            is_frozen=bool(c[7]),
            is_active=bool(c[8]),
            created_at=str(c[9]) if c[9] else None,
            last_used_at=str(c[10]) if c[10] else None,
            card_type=c[11] if len(c) > 11 else 'standard'
        ) for c in results] if results else []

    def resolve_card_transactions(self, info, card_id):
        """
        Vulnerability: BOLA - no ownership check
        Vulnerability: SQL injection
        """
        query = f"""
            SELECT ct.*, vc.card_number FROM card_transactions ct
            JOIN virtual_cards vc ON ct.card_id = vc.id
            WHERE ct.card_id = {card_id}
            ORDER BY ct.timestamp DESC
        """
        results = execute_query(query)
        return [CardTransactionType(
            id=t[0],
            card_id=t[1],
            amount=float(t[2]),
            merchant_name=t[3],
            transaction_type=t[4],
            status=t[5],
            timestamp=str(t[6]),
            description=t[7]
        ) for t in results] if results else []

    def resolve_bill_categories(self, info):
        """Public endpoint - no authentication required"""
        query = "SELECT * FROM bill_categories WHERE is_active = 1"
        results = execute_query(query)
        return [BillCategoryType(
            id=c[0],
            name=c[1],
            description=c[2],
            is_active=bool(c[3])
        ) for c in results] if results else []

    def resolve_billers_by_category(self, info, category_id):
        """
        Vulnerability: SQL injection possible
        """
        query = f"""
            SELECT * FROM billers
            WHERE category_id = {category_id} AND is_active = 1
        """
        results = execute_query(query)
        return [BillerType(
            id=b[0],
            category_id=b[1],
            name=b[2],
            account_number=b[3],  # Vulnerability: exposing account numbers
            description=b[4],
            minimum_amount=float(b[5]) if b[5] else 0.0,
            maximum_amount=float(b[6]) if b[6] else None,
            is_active=bool(b[7])
        ) for b in results] if results else []

    def resolve_payment_history(self, info):
        """Get current user's payment history"""
        current_user = info.context.get('current_user')
        if not current_user:
            return []

        query = f"""
            SELECT bp.*, b.name as biller_name, bc.name as category_name, vc.card_number
            FROM bill_payments bp
            JOIN billers b ON bp.biller_id = b.id
            JOIN bill_categories bc ON b.category_id = bc.id
            LEFT JOIN virtual_cards vc ON bp.card_id = vc.id
            WHERE bp.user_id = {current_user['user_id']}
            ORDER BY bp.created_at DESC
        """
        results = execute_query(query)
        return [BillPaymentType(
            id=p[0],
            user_id=p[1],
            biller_id=p[2],
            amount=float(p[3]),
            payment_method=p[4],
            card_id=p[5],
            reference_number=p[6],
            status=p[7],
            created_at=str(p[8]) if p[8] else None,
            processed_at=str(p[9]) if p[9] else None,
            description=p[10],
            biller_name=p[11] if len(p) > 11 else None,
            category_name=p[12] if len(p) > 12 else None
        ) for p in results] if results else []

    def resolve_user(self, info, username=None):
        """
        Vulnerability: SQL injection
        """
        if not username:
            return None
        query = f"SELECT * FROM users WHERE username='{username}'"
        result = execute_query(query)
        if result and len(result) > 0:
            row = result[0]
            return UserType(
                id=row[0],
                username=row[1],
                password=row[2],  # Vulnerability: exposing password
                account_number=row[3],
                balance=float(row[4]) if row[4] else 0.0,
                is_admin=bool(row[5]) if len(row) > 5 else False,
                profile_picture=row[6] if len(row) > 6 else None,
                reset_pin=row[7] if len(row) > 7 else None
            )
        return None

    def resolve_all_users(self, info):
        """
        Vulnerability: No authentication required
        Vulnerability: Exposes passwords and sensitive data
        """
        query = "SELECT * FROM users"
        results = execute_query(query)
        return [UserType(
            id=u[0],
            username=u[1],
            password=u[2],  # Vulnerability: exposing password
            account_number=u[3],
            balance=float(u[4]) if u[4] else 0.0,
            is_admin=bool(u[5]) if len(u) > 5 else False,
            profile_picture=u[6] if len(u) > 6 else None,
            reset_pin=u[7] if len(u) > 7 else None
        ) for u in results] if results else []

    def resolve_pending_loans(self, info):
        """
        Should require admin but doesn't check
        Vulnerability: Information disclosure
        """
        query = "SELECT * FROM loans WHERE status='pending'"
        results = execute_query(query)
        return [LoanType(
            id=l[0],
            user_id=l[1],
            amount=float(l[2]),
            status=l[3]
        ) for l in results] if results else []
