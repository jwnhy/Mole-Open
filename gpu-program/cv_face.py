import cv2

print(cv2.__version__, cv2.__path__, cv2.ocl.useOpenCL())

# Load pre-trained Haar feature classifier for face detection
face_cascade = cv2.CascadeClassifier('./haarcascade_frontalface_default.xml')

# Read the image of the face to be detected
image_path = 'face.jpg'
image = cv2.imread(image_path)

# Convert to greyscale
gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

# Detect faces in images using cascade classifiers
faces = face_cascade.detectMultiScale(gray, 1.1, 5)

# Draw a rectangle around each detected face
for (x, y, w, h) in faces:
	cv2.rectangle(image, (x, y), (x+w, y+h), (255, 0, 0), 2)

# Display image
cv2.imwrite('output.jpg', image)
