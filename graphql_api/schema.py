import graphene
from .queries import Query
from .mutations import Mutation

# Combine Query and Mutation into a single schema
schema = graphene.Schema(query=Query, mutation=Mutation)
