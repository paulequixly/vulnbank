from auth import verify_token


class AuthMiddleware:
    """
    GraphQL middleware to handle JWT authentication.
    Extracts token from Authorization header and adds user context.

    Vulnerability: Reuses the vulnerable JWT verification from auth.py
    which accepts 'none' algorithm and has other issues.
    """

    def resolve(self, next, root, info, **args):
        request = info.context.get('request')

        if request:
            auth_header = request.headers.get('Authorization')

            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                user = verify_token(token)  # Uses vulnerable verify_token
                if user:
                    info.context['current_user'] = user

            # Vulnerability: Also check query params
            elif hasattr(request, 'args') and request.args.get('token'):
                token = request.args.get('token')
                user = verify_token(token)
                if user:
                    info.context['current_user'] = user

            # Vulnerability: Also check cookies
            elif hasattr(request, 'cookies') and request.cookies.get('token'):
                token = request.cookies.get('token')
                user = verify_token(token)
                if user:
                    info.context['current_user'] = user

        return next(root, info, **args)
