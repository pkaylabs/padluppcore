from drf_spectacular.extensions import OpenApiSerializerFieldExtension


class CommaSeparatedListFieldExtension(OpenApiSerializerFieldExtension):
	"""Expose CommaSeparatedListField as List[str] in OpenAPI.

	Runtime behavior is implemented in `CommaSeparatedListField`.
	This extension only affects schema generation (Swagger / OpenAPI).
	"""

	target_class = 'api.serializers.CommaSeparatedListField'

	def map_serializer_field(self, auto_schema, direction):
		return {
			'type': 'array',
			'items': {'type': 'string'},
		}
