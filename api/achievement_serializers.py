from rest_framework import serializers


class AchievementRequirementSerializer(serializers.Serializer):
    key = serializers.CharField()
    label = serializers.CharField()
    current = serializers.IntegerField()
    target = serializers.IntegerField()


class AchievementSerializer(serializers.Serializer):
    key = serializers.CharField()
    name = serializers.CharField()
    description = serializers.CharField()
    current = serializers.IntegerField()
    target = serializers.IntegerField()
    eligible = serializers.BooleanField()
    earned_at = serializers.DateTimeField(allow_null=True)
    claimed_at = serializers.DateTimeField(allow_null=True)
    requirements = AchievementRequirementSerializer(many=True)


class LegacyAchievementSerializer(serializers.Serializer):
    key = serializers.CharField()
    name = serializers.CharField()
    unlocked_at = serializers.DateTimeField()


class AchievementCatalogSerializer(serializers.Serializer):
    achievements = AchievementSerializer(many=True)
    legacy_awards = LegacyAchievementSerializer(many=True, required=False)
