from flask import Blueprint, request, jsonify
from .schema import schema
from .middleware import AuthMiddleware
import json

graphql_bp = Blueprint('graphql', __name__)


GRAPHIQL_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>VulnBank GraphQL</title>
    <link href="https://cdn.jsdelivr.net/npm/graphiql@2.0.0/graphiql.min.css" rel="stylesheet" />
</head>
<body style="margin: 0;">
    <div id="graphiql" style="height: 100vh;"></div>
    <script crossorigin src="https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://cdn.jsdelivr.net/npm/react-dom@18/umd/react-dom.production.min.js"></script>
    <script crossorigin src="https://cdn.jsdelivr.net/npm/graphiql@2.0.0/graphiql.min.js"></script>
    <script>
        const fetcher = GraphiQL.createFetcher({
            url: '/graphql',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        ReactDOM.render(
            React.createElement(GraphiQL, { fetcher: fetcher }),
            document.getElementById('graphiql'),
        );
    </script>
</body>
</html>
'''


def get_context():
    """Build GraphQL context with request and user info"""
    context = {
        'request': request,
        'current_user': None
    }

    # Apply authentication from various sources
    auth_header = request.headers.get('Authorization')

    if auth_header and auth_header.startswith('Bearer '):
        from auth import verify_token
        token = auth_header.split(' ')[1]
        user = verify_token(token)
        if user:
            context['current_user'] = user

    # Vulnerability: Also check query params
    elif request.args.get('token'):
        from auth import verify_token
        token = request.args.get('token')
        user = verify_token(token)
        if user:
            context['current_user'] = user

    # Vulnerability: Also check cookies
    elif request.cookies.get('token'):
        from auth import verify_token
        token = request.cookies.get('token')
        user = verify_token(token)
        if user:
            context['current_user'] = user

    return context


@graphql_bp.route('/graphql', methods=['GET', 'POST'])
def graphql_endpoint():
    """
    GraphQL endpoint supporting both queries/mutations and GraphiQL interface.
    Vulnerability: Introspection enabled, no rate limiting
    """
    # Return GraphiQL interface for GET requests
    if request.method == 'GET':
        return GRAPHIQL_HTML, 200, {'Content-Type': 'text/html'}

    # Handle GraphQL POST requests
    try:
        data = request.get_json()

        if not data:
            return jsonify({'errors': [{'message': 'No JSON data provided'}]}), 400

        query = data.get('query')
        variables = data.get('variables')
        operation_name = data.get('operationName')

        if not query:
            return jsonify({'errors': [{'message': 'No query provided'}]}), 400

        # Build context with authentication
        context = get_context()

        # Execute GraphQL query using graphene's schema.execute
        result = schema.execute(
            query,
            variable_values=variables,
            operation_name=operation_name,
            context=context
        )

        response = {}
        if result.data:
            response['data'] = result.data
        if result.errors:
            response['errors'] = [
                {
                    'message': str(error.message),
                    'locations': [{'line': loc.line, 'column': loc.column} for loc in error.locations] if error.locations else None,
                    'path': error.path
                }
                for error in result.errors
            ]

        return jsonify(response)

    except json.JSONDecodeError:
        return jsonify({'errors': [{'message': 'Invalid JSON'}]}), 400
    except Exception as e:
        # Vulnerability: Detailed error exposure
        return jsonify({'errors': [{'message': str(e)}]}), 500
