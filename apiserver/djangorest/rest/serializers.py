from rest_framework import serializers

class ParamsSerializer(serializers.Serializer):
  email = serializers.EmailField()
  domain = serializers.CharField()
  type_req = serializers.ChoiceField(choices=['create', 'renew'])

  
