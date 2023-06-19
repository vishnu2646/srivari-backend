from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from account.models import AboutBlocks, AboutContent, Carosel, Endoresment, Enquiry, Home, HomePoints, VillsCarosel
from account.serializers import (
    AboutBlockSerializer,
    AboutContentSerializer,
    CaroselSerializer,
    EndoresmentSerializer,
    HomePointsSerializer,
    HomeSerializer,
    SendPasswordResetEmailSerializer,
    UserChangePasswordSerializer,
    UserLoginSerializer,
    UserPasswordResetSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
    EnquirySerializer,
    VillaCaroselSerializer
)
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes

# Generate Token Manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
    
@api_view(['GET'])
@permission_classes([IsAdminUser])
def isUserAdmin(request):
    content = {
        'msg': True
    }
    return Response(content)

@api_view(['GET'])
def admin_user(request):
    if request.user.is_authenticated and request.user.is_admin:
        return Response({"admin": True})
    else:
        return Response({"admin": False})

@api_view(['GET'])
def userIsLoggedIn(request):
    if request.user.is_authenticated:
        return Response({"LoggedIn": True})
    else:
        return Response({"LoggedIn": False})

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors':'Email or Password is not Valid'}, status=status.HTTP_404_NOT_FOUND)

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)

@api_view(['GET'])
def enquiryList(request):
    enquires = Enquiry.objects.all()
    serializer = EnquirySerializer(enquires, many=True)
    if request.user.is_authenticated and request.user.is_admin:
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response({'msg':'You are Not Authorised to view this data'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['GET'])
def enquiryDetail(request, pk):
    enquiry = Enquiry.objects.get(id=pk)
    serializer = EnquirySerializer(enquiry, many=False)
    if request.user.is_authenticated and request.user.is_admin:
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response({'msg':'You are Not Authorised to view this data'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['POST'])
def enquiryCreate(request):
    serializer = EnquirySerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
    return Response("You Will be contacted soon", status=status.HTTP_200_OK)

@api_view(['POST'])
def enquiryUpdate(request, pk):
    isAdmin = isUserAdmin
    if isAdmin:
        enquiry = Enquiry.objects.get(id=pk)
        serializer = EnquirySerializer(instance=enquiry, data=request.data)
        if serializer.is_valid():
            serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response({'msg':'You are Not Authorised to view this data'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['DELETE'])
def enquiryDelete(request, pk):
    isAdmin = isUserAdmin
    if isAdmin:
        enquiry = Enquiry.objects.get(id=pk)
        enquiry.delete()
        return Response({'msg': 'Deleted Successfully'}, status=status.HTTP_200_OK)
    else:
        return Response({'msg': 'You are Not Admin user to Access the data'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['GET'])
def endoresmentList(request):
    isAdmin = isUserAdmin
    if isAdmin:
        endoresment = Endoresment.objects.all()
        serializer = EndoresmentSerializer(endoresment, many=True, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    
@api_view(['GET'])
def endoresmentDetail(request, pk):
    endoresment = Endoresment.objects.get(id=pk)
    serializer = EndoresmentSerializer(endoresment, many=False)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
def endoresmentCreate(request):
    isAdmin = isUserAdmin
    if isAdmin:
        serializer = EndoresmentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response({'msg':'You are Not Authorised to view this data'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def endoresmentUpdate(request, pk):
    isAdmin = isUserAdmin
    if isAdmin:
        endoresment = Endoresment.objects.get(id=pk)
        serializer = EndoresmentSerializer(instance=endoresment, data=request.data)
        if serializer.is_valid():
            serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response({'msg':'You are Not Authorised to view this data'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['DELETE'])
def endoresmentDelete(request, pk):
    isAdmin = isUserAdmin
    if isAdmin:
        endoresment = Endoresment.objects.get(id=pk)
        endoresment.delete()
        return Response({'msg': 'Deleted Successfully'}, status=status.HTTP_200_OK)
    else:
        return Response({'msg': 'You are Not Admin user to Access the data'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['GET'])
def caroselView(request):
    carosel = Carosel.objects.all()
    serializer = CaroselSerializer(carosel, many=True, context={"request": request})
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def AboutContents(request):
    aboutContent = AboutContent.objects.all()
    serializer = AboutContentSerializer(aboutContent, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def AboutBlock(request):
    block = AboutBlocks.objects.all()
    serializer = AboutBlockSerializer(block, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def HomeView(request):
    block = Home.objects.all()
    serializer = HomeSerializer(block, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def HomePointsView(request):
    points = HomePoints.objects.all()
    serializer = HomePointsSerializer(points, many=True, context={"request": request})
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def villaCaroselView(request):
    villaCarosels = VillsCarosel.objects.all()
    serializer = VillaCaroselSerializer(villaCarosels, many=True, context={"request": request})
    return Response(serializer.data, status=status.HTTP_200_OK)