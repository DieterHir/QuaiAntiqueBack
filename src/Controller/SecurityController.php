<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\{JsonResponse, Request, Response};
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Serializer\Normalizer\AbstractNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Nelmio\ApiDocBundle\src\Annotation\Model;
use Nelmio\ApiDocBundle\src\Annotation\Security;
use OpenApi\Attributes as OA;

#[Route('/api', name: 'app_api_')]
class SecurityController extends AbstractController
{
    public function __construct(private SerializerInterface $serializer, private EntityManagerInterface $manager, private UserRepository $repository, private UrlGeneratorInterface $urlGenerator)
    {
    }

    #[Route('/registration', name: 'registration', methods: 'POST')]
    /**
     * @OA\Post(
     *  path="",
     *  summary="Inscription d'un nouvel utilisateur",
     * @OA\RequestBody(
     *  required==true,
     * description="Données de l'utilisateur à inscrire",
     * @OA\JsonContent(
     *  type="object",
     * @OA\Property(property="email", type="string", example="adresse@email.com")
     * )
     * )
     */
    public function register(Request $request, UserPasswordHasherInterface $passwordHasher): JsonResponse
    {
        $user = $this->serializer->deserialize($request->getContent(), User::class, 'json');
        $user->setPassword($passwordHasher->hashPassword($user, $user->getPassword()));
        $user->setCreatedAt(new DateTimeImmutable());

        $this->manager->persist($user);
        $this->manager->flush();

        return new JsonResponse(
            ['user' => $user->getUserIdentifier(), 'apiToken' => $user->getApiToken(), 'roles' => $user->getRoles()],
            Response::HTTP_CREATED
        );
    }

    #[Route('/login', name: 'login', methods: 'POST')]
    public function login(#[CurrentUser] ?User $user): JsonResponse
    {
        if (null === $user) {
            return new JsonResponse(
                [
                    'message' => 'missing credentials'
                ],
                Response::HTTP_UNAUTHORIZED
            );
        }

        return new JsonResponse(
            [
                'user' => $user->getUserIdentifier(),
                'apiToken' => $user->getApiToken(),
                'roles' => $user->getRoles()
            ]
        );
    }

    #[Route('/me', name: 'me', methods: 'GET')]
    public function me(#[CurrentUser] ?User $user): JsonResponse
    {
        $data = $this->serializer->serialize($user, 'json');

        return new JsonResponse($data, Response::HTTP_ACCEPTED);
    }

    #[Route('/{id}', name: 'edit', methods: 'PUT')]
    public function edit(Request $request, int $id, UserPasswordHasherInterface $passwordHasher): JsonResponse
    {
        $user = $this->repository->findOneBy(['id' => $id]);

        if ($user) {
            $user = $this->serializer->deserialize(
                $request->getContent(),
                User::class,
                'json',
                [AbstractNormalizer::OBJECT_TO_POPULATE => $user]
            );
            $user->setPassword($passwordHasher->hashPassword($user, $user->getPassword()));
            $user->setUpdatedAt(new DateTimeImmutable());

            $this->manager->flush();

            $responseData = $this->serializer->serialize($user, 'json');
            $location = $this->urlGenerator->generate(
                'app_api_me',
                ['id' => $user->getId()],
                UrlGeneratorInterface::ABSOLUTE_URL,
            );

            return new JsonResponse($responseData, Response::HTTP_ACCEPTED, ["Location" => $location]);
        }
    }
}
