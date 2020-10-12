import setuptools

setuptools.setup(
    name="sspvo",
    version="0.1.0",
    author="Artem V. Zaborskiy",
    author_email="ftomza@yandex.ru",
    description="Module for working with Суперсервис 'Поступление в ВУЗ онлайн'",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "pygost~=5.1",
        "pem~=20.1",
        "pydersan~=8.1",
    ]
)