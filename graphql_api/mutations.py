import graphene
import random
import string
import time
from datetime import datetime, timedelta

from database import execute_query, execute_transaction
from auth import generate_token
from .types import (
    AuthPayloadType, TransferResultType, CardCreateResultType,
    CardUpdateResultType, BillPaymentResultType, LoanResultType,
    DeleteResultType
)


def generate_account_number():
    return ''.join(random.choices(string.digits, k=10))


def generate_card_number():
    return ''.join(random.choices(string.digits, k=16))


def generate_cvv():
    return ''.join(random.choices(string.digits, k=3))


# Authentication Mutations
class Login(graphene.Mutation):
    """
    Login mutation
    Vulnerability: SQL injection in username/password
    """
    class Arguments:
        username = graphene.String(required=True)
        password = graphene.String(required=True)

    Output = AuthPayloadType

    def mutate(self, info, username, password):
        # Vulnerability: SQL injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        result = execute_query(query)

        if result and len(result) > 0:
            user = result[0]
            token = generate_token(user[0], user[1], user[5])
            return AuthPayloadType(
                status='success',
                message='Login successful',
                token=token,
                account_number=user[3],
                is_admin=bool(user[5]),
                debug_info={
                    'user_id': user[0],
                    'username': user[1],
                    'login_time': str(datetime.now())
                }
            )
        return AuthPayloadType(
            status='error',
            message='Invalid credentials',
            debug_info={'attempted_username': username, 'time': str(datetime.now())}
        )


class Register(graphene.Mutation):
    """
    Register mutation
    Vulnerability: Mass assignment - can set is_admin and balance
    """
    class Arguments:
        username = graphene.String(required=True)
        password = graphene.String(required=True)
        is_admin = graphene.Boolean()  # Vulnerability: mass assignment
        balance = graphene.Float()  # Vulnerability: mass assignment

    Output = AuthPayloadType

    def mutate(self, info, username, password, is_admin=False, balance=1000.0):
        account_number = generate_account_number()

        # Check existing user
        existing = execute_query(
            "SELECT username FROM users WHERE username = ?", (username,)
        )
        if existing and len(existing) > 0:
            return AuthPayloadType(status='error', message='Username already exists')

        # Vulnerability: accepts is_admin and balance from input
        admin_val = 1 if is_admin else 0
        query = """
            INSERT INTO users (username, password, account_number, balance, is_admin)
            VALUES (?, ?, ?, ?, ?)
        """
        execute_query(query, (username, password, account_number, balance, admin_val), fetch=False)

        # Fetch the created user
        new_user = execute_query(
            "SELECT id, username, account_number, balance, is_admin FROM users WHERE username = ?",
            (username,)
        )

        if new_user and len(new_user) > 0:
            user = new_user[0]
            return AuthPayloadType(
                status='success',
                message='Registration successful',
                account_number=user[2],
                is_admin=bool(user[4]),
                debug_info={
                    'user_id': user[0],
                    'balance': float(user[3]),
                    'fields_registered': ['username', 'password', 'is_admin', 'balance']
                }
            )
        return AuthPayloadType(status='error', message='Registration failed')


# Account Mutations
class Transfer(graphene.Mutation):
    """
    Transfer mutation
    Vulnerability: Negative amounts allowed, race condition
    """
    class Arguments:
        to_account = graphene.String(required=True)
        amount = graphene.Float(required=True)
        description = graphene.String()

    Output = TransferResultType

    def mutate(self, info, to_account, amount, description='Transfer'):
        current_user = info.context.get('current_user')
        if not current_user:
            return TransferResultType(status='error', message='Authentication required')

        # Get sender info
        sender = execute_query(
            "SELECT account_number, balance FROM users WHERE id = ?",
            (current_user['user_id'],)
        )
        if not sender or len(sender) == 0:
            return TransferResultType(status='error', message='User not found')

        sender = sender[0]
        from_account = sender[0]
        balance = float(sender[1])

        # Vulnerability: no negative amount check
        if balance >= abs(amount):
            queries = [
                ("UPDATE users SET balance = balance - ? WHERE id = ?",
                 (amount, current_user['user_id'])),
                ("UPDATE users SET balance = balance + ? WHERE account_number = ?",
                 (amount, to_account)),
                ("""INSERT INTO transactions
                    (from_account, to_account, amount, transaction_type, description)
                    VALUES (?, ?, ?, ?, ?)""",
                 (from_account, to_account, amount, 'transfer', description))
            ]
            execute_transaction(queries)
            return TransferResultType(
                status='success',
                message='Transfer completed',
                new_balance=balance - amount
            )
        return TransferResultType(status='error', message='Insufficient funds')


# Virtual Card Mutations
class CreateVirtualCard(graphene.Mutation):
    """
    Create virtual card mutation
    Vulnerability: SQL injection in card_type
    """
    class Arguments:
        card_limit = graphene.Float()
        card_type = graphene.String()

    Output = CardCreateResultType

    def mutate(self, info, card_limit=1000.0, card_type='standard'):
        current_user = info.context.get('current_user')
        if not current_user:
            return CardCreateResultType(status='error', message='Authentication required')

        card_number = generate_card_number()
        cvv = generate_cvv()
        expiry_date = (datetime.now() + timedelta(days=365)).strftime('%m/%y')

        # Vulnerability: SQL injection in card_type
        query = f"""
            INSERT INTO virtual_cards
            (user_id, card_number, cvv, expiry_date, card_limit, card_type)
            VALUES
            ({current_user['user_id']}, '{card_number}', '{cvv}', '{expiry_date}', {card_limit}, '{card_type}')
        """
        execute_query(query, fetch=False)

        return CardCreateResultType(
            status='success',
            message='Virtual card created',
            card_number=card_number,
            cvv=cvv,  # Vulnerability: exposing CVV
            expiry_date=expiry_date,
            card_limit=card_limit,
            card_type=card_type
        )


class ToggleCardFreeze(graphene.Mutation):
    """
    Toggle card freeze status
    Vulnerability: BOLA - no ownership check
    """
    class Arguments:
        card_id = graphene.Int(required=True)

    Output = CardUpdateResultType

    def mutate(self, info, card_id):
        # Vulnerability: BOLA - no verification card belongs to user
        query = f"""
            UPDATE virtual_cards SET is_frozen = NOT is_frozen
            WHERE id = {card_id}
        """
        execute_query(query, fetch=False)

        # Get updated status
        result = execute_query(f"SELECT is_frozen FROM virtual_cards WHERE id = {card_id}")
        if result and len(result) > 0:
            return CardUpdateResultType(
                status='success',
                message=f"Card {'frozen' if result[0][0] else 'unfrozen'}",
                is_frozen=bool(result[0][0])
            )
        return CardUpdateResultType(status='error', message='Card not found')


class UpdateCardLimit(graphene.Mutation):
    """
    Update card limit
    Vulnerability: BOLA, mass assignment allows updating balance
    """
    class Arguments:
        card_id = graphene.Int(required=True)
        card_limit = graphene.Float()
        current_balance = graphene.Float()  # Vulnerability: mass assignment

    Output = CardUpdateResultType

    def mutate(self, info, card_id, card_limit=None, current_balance=None):
        # Vulnerability: BOLA - no ownership check
        # Vulnerability: Mass assignment - can update balance
        updates = []
        values = []

        if card_limit is not None:
            updates.append("card_limit = ?")
            values.append(card_limit)
        if current_balance is not None:  # Mass assignment vulnerability
            updates.append("current_balance = ?")
            values.append(current_balance)

        if not updates:
            return CardUpdateResultType(status='error', message='No updates provided')

        query = f"""
            UPDATE virtual_cards SET {', '.join(updates)}
            WHERE id = {card_id}
        """
        execute_query(query, tuple(values), fetch=False)

        # Get updated card
        result = execute_query(f"SELECT card_limit, current_balance FROM virtual_cards WHERE id = {card_id}")
        if result and len(result) > 0:
            return CardUpdateResultType(
                status='success',
                message='Card updated',
                card_limit=float(result[0][0]),
                current_balance=float(result[0][1])
            )
        return CardUpdateResultType(status='error', message='Card not found')


# Bill Payment Mutations
class CreateBillPayment(graphene.Mutation):
    """
    Create bill payment
    Vulnerability: BOLA on card_id, no amount validation
    """
    class Arguments:
        biller_id = graphene.Int(required=True)
        amount = graphene.Float(required=True)
        payment_method = graphene.String(required=True)
        card_id = graphene.Int()
        description = graphene.String()

    Output = BillPaymentResultType

    def mutate(self, info, biller_id, amount, payment_method, card_id=None, description='Bill Payment'):
        current_user = info.context.get('current_user')
        if not current_user:
            return BillPaymentResultType(status='error', message='Authentication required')

        reference = f"BILL{int(time.time())}"  # Vulnerability: predictable reference

        queries = [
            ("""INSERT INTO bill_payments
                (user_id, biller_id, amount, payment_method, card_id, reference_number, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
             (current_user['user_id'], biller_id, amount, payment_method, card_id, reference, description))
        ]

        # Vulnerability: BOLA - no verification card belongs to user
        if payment_method == 'virtual_card' and card_id:
            queries.append((
                "UPDATE virtual_cards SET current_balance = current_balance - ? WHERE id = ?",
                (amount, card_id)
            ))
        else:
            queries.append((
                "UPDATE users SET balance = balance - ? WHERE id = ?",
                (amount, current_user['user_id'])
            ))

        execute_transaction(queries)

        return BillPaymentResultType(
            status='success',
            message='Payment processed',
            reference=reference,
            amount=amount,
            payment_method=payment_method,
            timestamp=str(datetime.now())
        )


# Loan Mutations
class RequestLoan(graphene.Mutation):
    """Request a loan"""
    class Arguments:
        amount = graphene.Float(required=True)

    Output = LoanResultType

    def mutate(self, info, amount):
        current_user = info.context.get('current_user')
        if not current_user:
            return LoanResultType(status='error', message='Authentication required')

        execute_query(
            "INSERT INTO loans (user_id, amount) VALUES (?, ?)",
            (current_user['user_id'], amount),
            fetch=False
        )
        return LoanResultType(
            status='success',
            message='Loan requested successfully',
            amount=amount
        )


class ApproveLoan(graphene.Mutation):
    """
    Approve a loan (admin only)
    Vulnerability: Race condition, no atomicity check
    """
    class Arguments:
        loan_id = graphene.Int(required=True)

    Output = LoanResultType

    def mutate(self, info, loan_id):
        current_user = info.context.get('current_user')
        if not current_user or not current_user.get('is_admin'):
            return LoanResultType(status='error', message='Admin access required')

        loan = execute_query("SELECT * FROM loans WHERE id = ?", (loan_id,))
        if loan and len(loan) > 0:
            loan = loan[0]
            queries = [
                ("UPDATE loans SET status='approved' WHERE id = ?", (loan_id,)),
                ("UPDATE users SET balance = balance + ? WHERE id = ?", (float(loan[2]), loan[1]))
            ]
            execute_transaction(queries)
            return LoanResultType(
                status='success',
                message='Loan approved',
                loan_id=loan_id,
                amount=float(loan[2]),
                debug_info={'approved_by': current_user['username']}
            )
        return LoanResultType(status='error', message='Loan not found')


# Admin Mutations
class DeleteAccount(graphene.Mutation):
    """
    Delete user account (admin only)
    Vulnerability: No confirmation, no audit logging
    """
    class Arguments:
        user_id = graphene.Int(required=True)

    Output = DeleteResultType

    def mutate(self, info, user_id):
        current_user = info.context.get('current_user')
        if not current_user or not current_user.get('is_admin'):
            return DeleteResultType(status='error', message='Admin access required')

        execute_query("DELETE FROM users WHERE id = ?", (user_id,), fetch=False)
        return DeleteResultType(status='success', message='Account deleted')


class CreateAdmin(graphene.Mutation):
    """
    Create admin account (admin only)
    Vulnerability: SQL injection
    """
    class Arguments:
        username = graphene.String(required=True)
        password = graphene.String(required=True)

    Output = DeleteResultType

    def mutate(self, info, username, password):
        current_user = info.context.get('current_user')
        if not current_user or not current_user.get('is_admin'):
            return DeleteResultType(status='error', message='Admin access required')

        account_number = generate_account_number()
        # Vulnerability: SQL injection
        query = f"INSERT INTO users (username, password, account_number, is_admin) VALUES ('{username}', '{password}', '{account_number}', 1)"
        execute_query(query, fetch=False)
        return DeleteResultType(status='success', message='Admin created')


# Combine all mutations
class Mutation(graphene.ObjectType):
    # Authentication
    login = Login.Field()
    register = Register.Field()

    # Account operations
    transfer = Transfer.Field()

    # Virtual cards
    create_virtual_card = CreateVirtualCard.Field()
    toggle_card_freeze = ToggleCardFreeze.Field()
    update_card_limit = UpdateCardLimit.Field()

    # Bill payments
    create_bill_payment = CreateBillPayment.Field()

    # Loans
    request_loan = RequestLoan.Field()
    approve_loan = ApproveLoan.Field()

    # Admin
    delete_account = DeleteAccount.Field()
    create_admin = CreateAdmin.Field()
