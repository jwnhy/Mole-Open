#include <opencv2/opencv.hpp>
#include <opencv2/core/ocl.hpp>
#include <iostream>
#include <unistd.h>
#include <dlfcn.h>
#include <CL/cl.h>

int main(int argc, char** argv) {
    std::cout << "OpenCV version: " << CV_VERSION << std::endl;
    std::cout << "OpenCL Available: " << cv::ocl::haveOpenCL() << std::endl;
    std::cout << "OpenCL in Use: " << cv::ocl::useOpenCL() << std::endl;

    char img_path[256] = "/home/radxa/csfparser/gpu-program/edge.jpg";
    if (argc == 2) strcpy(img_path, argv[1]);

    cv::Mat c_image;
    c_image = cv::imread(img_path, cv::IMREAD_GRAYSCALE);

    std::cout << "Image Values:" << std::endl;
    for (int j = 0 ; j < 10 ; ++ j)
        printf("0x%x\n", c_image.at<int>(j, 0));
        // std::cout << c_image.at<int>(j, 0) << std::endl;

    if (c_image.empty()) {
        std::cerr << "Error: Cannot find" << img_path <<std::endl;
        return -1;
    }

    cv::UMat d_image;
    c_image.copyTo(d_image);

    cv::UMat edges;
    cv::Canny(d_image, edges, 100, 200);

    cv::Mat c_result;
    edges.copyTo(c_result);
    for (int j = 0 ; j < 10 ; ++ j)
        printf("0x%x\n", c_result.at<int>(j, 0));
        // std::cout << c_result.at<int>(j, 0) << std::endl;
    
    cv::imwrite("output.jpg", c_result);
    
    return 0;
}
