from rest_framework import serializers
from .models import CommunityReport

class CommunityReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityReport
        fields = "__all__"

