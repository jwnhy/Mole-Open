#include <opencv2/opencv.hpp>
#include <opencv2/core/ocl.hpp>
#include <iostream>

int main(int argc, char** argv) {
    std::cout << "OpenCV version: " << CV_VERSION << std::endl;
    std::cout << "OpenCL Available: " << cv::ocl::haveOpenCL() << std::endl;
    std::cout << "OpenCL in Use: " << cv::ocl::useOpenCL() << std::endl;

    char img_path[256] = "./face.jpg";
    if (argc == 2) strcpy(img_path, argv[1]);

    char faceCascadePath[] = "haarcascade_frontalface_default.xml";
    cv::CascadeClassifier faceCascade;
    if (!faceCascade.load(cv::samples::findFile("haarcascade_frontalface.xml"))) {
        std::cerr << "Error loading face cascade XML file!" << std::endl;
        return -1;
    }

    cv::Mat image = cv::imread(img_path);
    if (image.empty()) {
        std::cerr << "Could not open or find the image!" << std::endl;
        return -1;
    }

    cv::Mat gray;
    cvtColor(image, gray, cv::COLOR_BGR2GRAY); 

    cv::UMat d_gray;
    gray.copyTo(d_gray);

    std::vector<cv::Rect> faces;
    faceCascade.detectMultiScale(d_gray, faces, 1.1, 5);

    for (const auto& face : faces) {
        std::cout << "[...] " << face << std::endl;
        rectangle(image, face, cv::Scalar(255, 0, 0), 2);
    }

    cv::imwrite("output.jpg", image);

    return 0;
}
