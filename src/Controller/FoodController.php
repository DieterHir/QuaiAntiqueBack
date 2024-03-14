<?php

namespace App\Controller;

use App\Entity\Food;
use App\Repository\FoodRepository;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Serializer\Normalizer\AbstractNormalizer;
use Symfony\Component\Serializer\SerializerInterface;

#[Route('api/food', name: 'app_api_food_')]

class FoodController extends AbstractController
{

    public function __construct(private SerializerInterface $serializer, private UrlGeneratorInterface $urlGenerator, private EntityManagerInterface $manager, private FoodRepository $repository)
    {
    }

    #[Route(name: 'new', methods: 'POST')]
    public function new(Request $request): Response
    {
        $food = $this->serializer->deserialize($request->getContent(), Food::class, "json");
        $food->setCreatedAt(new DateTimeImmutable());

        $this->manager->persist($food);
        $this->manager->flush();

        $responseData = $this->serializer->serialize($food, 'json');
        $location = $this->urlGenerator->generate(
            'app_api_food_show',
            ['id' => $food->getId()],
            UrlGeneratorInterface::ABSOLUTE_URL,
        );

        return new JsonResponse($responseData, Response::HTTP_CREATED, ["location" => $location]);
    }

    #[Route('/{id}', name: 'show', methods: 'GET')]
    public function show(int $id): Response
    {
        $food = $this->repository->findOneBy(['id' => $id]);

        if ($food) {
            $responseData = $this->serializer->serialize($food, 'json');

            return new JsonResponse($responseData, Response::HTTP_OK, [], true);
        }

        return new JsonResponse(null, Response::HTTP_NOT_FOUND);
    }

    #[Route('/{id}', name: 'edit', methods: 'PUT')]
    public function edit(int $id, Request $request): Response
    {
        $food = $this->repository->findOneBy(['id' => $id]);

        if ($food) {
            $food = $this->serializer->deserialize(
                $request->getContent(),
                Food::class,
                'json',
                [AbstractNormalizer::OBJECT_TO_POPULATE => $food]
            );
            $food->setUpdatedAt(new DateTimeImmutable());

            $this->manager->flush();

            $responseData = $this->serializer->serialize($food, 'json');
            $location = $this->urlGenerator->generate(
                'app_api_food_show',
                ['id' => $food->getId()],
                UrlGeneratorInterface::ABSOLUTE_URL,
            );

            return new JsonResponse($responseData, Response::HTTP_ACCEPTED, ["Location" => $location]);
        }

        return new JsonResponse(null, Response::HTTP_NOT_FOUND);
    }

    #[Route('/{id}', name: 'delete', methods: 'DELETE')]
    public function delete(int $id): Response
    {
        $food = $this->repository->findOneBy(['id' => $id]);

        if ($food) {
            $this->manager->remove($food);
            $this->manager->flush();

            return new JsonResponse(null, Response::HTTP_NO_CONTENT);
        }

        return new JsonResponse(null, Response::HTTP_NOT_FOUND);
    }
}
