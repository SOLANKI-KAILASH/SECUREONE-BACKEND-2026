from django.shortcuts import render
import requests
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

## password breach checker

import hashlib

HIBP_API = "https://api.pwnedpasswords.com/range/"

@api_view(["POST"])
def password_breach_check(request):
    password = request.data.get("password")

    if not password:
        return Response(
            {"error": "Password is required"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # 1. Convert password to SHA-1 hash
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # 2. Apply k-anonymity
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # 3. Call HIBP API with prefix only
    hibp_response = requests.get(f"{HIBP_API}{prefix}")

    if hibp_response.status_code != 200:
        return Response(
            {"error": "HIBP service unavailable"},
            status=status.HTTP_503_SERVICE_UNAVAILABLE
        )

    # 4. Compare hash suffix locally
    for line in hibp_response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return Response({
                "breached": True,
                "breach_count": int(count),
                "risk_level": "High",
                "message": "This password has appeared in data breaches."
            })

    # 5. Safe password
    return Response({
        "breached": False,
        "breach_count": 0,
        "risk_level": "Safe",
        "message": "This password has not been found in known breaches."
    })



###



IP2WHOIS_KEY = "6E9D99599927A1F41B3A664BA6A36FB6"

@api_view(["POST"])
def domain_info(request):
    domain = request.data.get("domain")
    if not domain:
        return Response({"error": "Domain is required"}, status=400)

    api_url = f"https://api.ip2whois.com/v2?key={IP2WHOIS_KEY}&domain={domain}"

    try:
        r = requests.get(api_url, timeout=10)
        r.raise_for_status()
        data = r.json()

        # Extract required fields
        result = {
            "domain": data.get("domain"),
            "domain_id": data.get("domain_id"),
            "status": data.get("status"),
            "create_date": data.get("create_date"),
            "update_date": data.get("update_date"),
            "expire_date": data.get("expire_date"),
            "domain_age": data.get("domain_age"),
            "whois_server": data.get("whois_server"),
            "registrar": data.get("registrar"),
            "registrant": data.get("registrant")
        }

        return Response(result)

    except requests.RequestException as e:
        return Response({"error": str(e)}, status=500)



@api_view(["POST"])
def ssl_check(request):
    domain = request.data.get("domain")
    if not domain:
        return Response({"error": "Domain is required"}, status=400)

    ssl_api_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&all=done"

    try:
        r = requests.get(ssl_api_url, timeout=30)
        r.raise_for_status()
        data = r.json()

        result = {
            "host": data.get("host"),
            "port": data.get("port"),
            "protocol": data.get("protocol"),
            "status": data.get("status"),
            "endpoints": data.get("endpoints", [])
        }

        return Response(result)

    except requests.RequestException as e:
        return Response({"error": str(e)}, status=500)
    

#report

from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import CommunityReport
from .serializers import CommunityReportSerializer

# Fetch all reports (community feed)
@api_view(["GET"])
def get_reports(request):
    reports = CommunityReport.objects.all().order_by("-created_at")  # latest first
    serializer = CommunityReportSerializer(reports, many=True)
    return Response(serializer.data)

# Post a new report
@api_view(["POST"])
def add_report(request):
    serializer = CommunityReportSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Report added successfully", "report": serializer.data})
    return Response(serializer.errors, status=400)

VERIROUTE_API_KEY = "mpl_live_pk_b1YG0Twg32hIonCkjc99o7BvAQBIkVDB92LU0mtsA5E"
VERIROUTE_API_URL = "https://api-service.verirouteintel.io/api/v1/cnam"


from django.http import JsonResponse
def check_phone(request):
    """
    Example Django view to check phone number spam/reputation.
    Expects GET parameter: ?phone=NUMBER
    """
    phone_number = request.GET.get("phone")
    if not phone_number:
        return JsonResponse({"error": "Phone number not provided"}, status=400)
    
    payload = {
        "phone_number": phone_number,
        "include_spam_check": True
    }
    headers = {
        "Authorization": f"Bearer {VERIROUTE_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(VERIROUTE_API_URL, json=payload, headers=headers)
        data = response.json()
        
        # Extract spam info
        result = {
            "number": phone_number,
            "spam_type": data.get("data", {}).get("spam_type", "UNKNOWN"),
            "caller_name": data.get("data", {}).get("cnam", "UNKNOWN")
        }
        return JsonResponse(result)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)